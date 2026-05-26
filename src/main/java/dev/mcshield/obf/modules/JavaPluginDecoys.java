package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.util.NameGenerator;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.FieldInsnNode;
import jdk.internal.org.objectweb.asm.tree.FieldNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.JumpInsnNode;
import jdk.internal.org.objectweb.asm.tree.LabelNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.TypeInsnNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Generates harmless JavaPlugin-looking decoys so scanner scripts cannot identify the real main
 * by searching for the only class that extends JavaPlugin / declares onEnable.
 *
 * Decoys are intentionally "fat". They get fields and lifecycle/payment/license-like
 * methods so simple heuristics such as method-count, field-count, or names like reloadPlugin/checkLicense
 * no longer isolate the real plugin main.
 */
public final class JavaPluginDecoys implements Opcodes {
    private final ObfConfig config;
    private final long seed;

    public JavaPluginDecoys(ObfConfig config, long seed) {
        this.config = config;
        this.seed = seed;
    }

    public Map<String, byte[]> generate() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.enabled("javaPluginDecoys", false)) return out;
        int count = Math.max(0, config.integer("javaPluginDecoys.classes", 32));
        if (count == 0) return out;
        String base = config.string("javaPluginDecoys.basePackage", "z/shadow");
        String style = config.string("javaPluginDecoys.style", config.string("renaming.style", "ascii"));
        int minDepth = config.integer("javaPluginDecoys.depthMin", 1);
        int maxDepth = Math.max(minDepth, config.integer("javaPluginDecoys.depthMax", 4));
        int minLen = config.integer("javaPluginDecoys.nameMinLength", 12);
        int maxLen = Math.max(minLen, config.integer("javaPluginDecoys.nameMaxLength", 36));
        Random rnd = new Random(seed ^ 0x5a17d3c0L);
        NameGenerator gen = new NameGenerator(style, minLen, maxLen, rnd);
        for (int i = 0; i < count; i++) {
            String owner = gen.nextInternalClass(base, minDepth, maxDepth, rnd);
            out.put(owner, make(owner, i, rnd));
        }
        return out;
    }

    private byte[] make(String owner, int id, Random rnd) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = owner;
        cn.superName = "org/bukkit/plugin/java/JavaPlugin";
        cn.sourceFile = config.string("javaPluginDecoys.sourceFile", "entry.c");
        cn.sourceDebug = "SMAP\n" + cn.sourceFile + "\nC\n*S C\n*F\n+ 1 " + cn.sourceFile + "\n" + cn.sourceFile + "\n*L\n1#1,4096:1\n*E";

        int fieldCount = Math.max(0, config.integer("javaPluginDecoys.fieldCount", 24));
        int methodCount = Math.max(5, config.integer("javaPluginDecoys.methodCount", 96));
        addFields(cn, owner, fieldCount, rnd);
        addConstructor(cn, owner, fieldCount, id);
        addLifecycle(cn, owner, id);
        addSensitiveNamedMethods(cn, owner, id);
        addBulkMethods(cn, owner, Math.max(0, methodCount - cn.methods.size()), rnd);

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private void addFields(ClassNode cn, String owner, int fieldCount, Random rnd) {
        List<String> names = new ArrayList<>();
        names.addAll(List.of(
                "licenseManager", "pendingCards", "bankPaymentManager", "paymentGuiManager",
                "configManager", "databaseManager", "milestoneManager", "scheduler", "api",
                "pending", "pendingPayments", "paymentCache", "httpClient", "plugin", "commands",
                "reloadToken", "lastCheck", "enabled", "debug", "service", "registry", "provider"
        ));
        for (int i = 0; i < fieldCount; i++) {
            String name = i < names.size() ? names.get(i) : "cache" + i;
            String desc;
            int kind = i % 6;
            if (kind == 0) desc = "Ljava/util/Map;";
            else if (kind == 1) desc = "Ljava/lang/Object;";
            else if (kind == 2) desc = "Ljava/lang/String;";
            else if (kind == 3) desc = "Ljava/util/List;";
            else if (kind == 4) desc = "I";
            else desc = "Z";
            cn.fields.add(new FieldNode(ACC_PRIVATE, name, desc, null, null));
        }
    }

    private void addConstructor(ClassNode cn, String owner, int fieldCount, int id) {
        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "org/bukkit/plugin/java/JavaPlugin", "<init>", "()V", false));
        for (int i = 0; i < fieldCount; i++) {
            FieldNode fn = (FieldNode) cn.fields.get(i);
            init.instructions.add(new VarInsnNode(ALOAD, 0));
            switch (fn.desc) {
                case "Ljava/util/Map;" -> {
                    init.instructions.add(new TypeInsnNode(NEW, "java/util/LinkedHashMap"));
                    init.instructions.add(new InsnNode(DUP));
                    init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/util/LinkedHashMap", "<init>", "()V", false));
                }
                case "Ljava/util/List;" -> {
                    init.instructions.add(new TypeInsnNode(NEW, "java/util/ArrayList"));
                    init.instructions.add(new InsnNode(DUP));
                    init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/util/ArrayList", "<init>", "()V", false));
                }
                case "Ljava/lang/String;" -> init.instructions.add(new LdcInsnNode("task-" + (id ^ i)));
                case "I" -> pushInt(init, id + i * 31);
                case "Z" -> init.instructions.add((id + i) % 2 == 0 ? new InsnNode(ICONST_1) : new InsnNode(ICONST_0));
                default -> init.instructions.add(new InsnNode(ACONST_NULL));
            }
            init.instructions.add(new FieldInsnNode(PUTFIELD, owner, fn.name, fn.desc));
        }
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);
    }

    private void addLifecycle(ClassNode cn, String owner, int id) {
        MethodNode onLoad = new MethodNode(ACC_PUBLIC, "onLoad", "()V", null, null);
        onLoad.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onLoad);

        MethodNode onEnable = new MethodNode(ACC_PUBLIC, "onEnable", "()V", null, null);
        addOpaqueNoop(onEnable, owner, id);
        onEnable.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onEnable);

        MethodNode onDisable = new MethodNode(ACC_PUBLIC, "onDisable", "()V", null, null);
        addOpaqueNoop(onDisable, owner, id ^ 0x55aa);
        onDisable.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onDisable);

        MethodNode onCommand = new MethodNode(ACC_PUBLIC, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", null, null);
        onCommand.instructions.add(new InsnNode(ICONST_0));
        onCommand.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(onCommand);

        MethodNode onTab = new MethodNode(ACC_PUBLIC, "onTabComplete", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;", null, null);
        onTab.instructions.add(new MethodInsnNode(INVOKESTATIC, "java/util/Collections", "emptyList", "()Ljava/util/List;", false));
        onTab.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(onTab);
    }

    private void addSensitiveNamedMethods(ClassNode cn, String owner, int id) {
        addVoid(cn, owner, "reloadPlugin", id);
        addBool(cn, owner, "checkLicense", id ^ 7);
        addObj(cn, owner, "createHttpClient", id ^ 11);
        addBool(cn, owner, "processSuccessPayment", id ^ 13);
        addBool(cn, owner, "processManualTopup", id ^ 17);
        addObj(cn, owner, "handleCardResponse", id ^ 19);
        addVoid(cn, owner, "giveCardReward", id ^ 23);
        addObj(cn, owner, "getPendingCards", id ^ 29);
        addVoid(cn, owner, "startBossBarTask", id ^ 31);
        addVoid(cn, owner, "runTimerAsync", id ^ 37);
        addVoid(cn, owner, "registerCommands", id ^ 41);
        addVoid(cn, owner, "loadConfig", id ^ 43);
        addVoid(cn, owner, "saveData", id ^ 47);
        addObj(cn, owner, "getApi", id ^ 53);
        addObj(cn, owner, "getPaymentManager", id ^ 59);
    }

    private void addBulkMethods(ClassNode cn, String owner, int extra, Random rnd) {
        NameGenerator gen = new NameGenerator(config.string("javaPluginDecoys.memberStyle", config.string("renaming.memberStyle", "ascii")),
                config.integer("javaPluginDecoys.memberNameMinLength", 10),
                config.integer("javaPluginDecoys.memberNameMaxLength", 32),
                rnd);
        for (int i = 0; i < extra; i++) {
            String n = gen.next();
            int kind = i % 5;
            if (kind == 0) addVoid(cn, owner, n, i);
            else if (kind == 1) addBool(cn, owner, n, i);
            else if (kind == 2) addInt(cn, owner, n, i);
            else if (kind == 3) addObj(cn, owner, n, i);
            else addString(cn, owner, n, i);
        }
    }

    private void addVoid(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()V", null, null);
        addOpaqueNoop(m, owner, id);
        m.instructions.add(new InsnNode(RETURN));
        cn.methods.add(m);
    }

    private void addBool(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()Z", null, null);
        addOpaqueNoop(m, owner, id);
        m.instructions.add((id & 1) == 0 ? new InsnNode(ICONST_0) : new InsnNode(ICONST_1));
        m.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(m);
    }

    private void addInt(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()I", null, null);
        pushInt(m, id * 31 + owner.length());
        m.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(m);
    }

    private void addObj(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()Ljava/lang/Object;", null, null);
        if (!cn.fields.isEmpty()) {
            FieldNode fn = (FieldNode) cn.fields.get(Math.floorMod(id, cn.fields.size()));
            m.instructions.add(new VarInsnNode(ALOAD, 0));
            m.instructions.add(new FieldInsnNode(GETFIELD, owner, fn.name, fn.desc));
            if (fn.desc.length() == 1) {
                // Primitive fields are not objects; just return null.
                m.instructions.add(new InsnNode(POP));
                m.instructions.add(new InsnNode(ACONST_NULL));
            }
        } else {
            m.instructions.add(new InsnNode(ACONST_NULL));
        }
        m.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(m);
    }

    private void addString(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()Ljava/lang/String;", null, null);
        m.instructions.add(new LdcInsnNode("kora-" + Integer.toHexString(id ^ owner.hashCode())));
        m.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(m);
    }

    private void addOpaqueNoop(MethodNode m, String owner, int id) {
        // Branch-free no-op keeps the generated decoy verifier-safe without needing StackMapTable.
        pushInt(m, id ^ owner.hashCode());
        pushInt(m, Integer.rotateLeft(id, 7) ^ owner.length());
        m.instructions.add(new InsnNode(IXOR));
        m.instructions.add(new InsnNode(POP));
    }

    private void pushInt(MethodNode m, int v) {
        if (v >= -1 && v <= 5) m.instructions.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) m.instructions.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) m.instructions.add(new IntInsnNode(SIPUSH, v));
        else m.instructions.add(new LdcInsnNode(v));
    }
}
