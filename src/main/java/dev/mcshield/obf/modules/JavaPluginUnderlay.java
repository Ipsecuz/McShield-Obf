package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.NameGenerator;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.FieldInsnNode;
import jdk.internal.org.objectweb.asm.tree.FieldNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
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
 * Inserts a decoy superclass chain below the real JavaPlugin main.
 *
 * Before:
 *   boot facade -> proxy -> realMain -> JavaPlugin
 * After:
 *   boot facade -> proxy -> realMain -> underlayA -> underlayB -> ... -> JavaPlugin
 *
 * This is intentionally safer than a full custom loader for state-heavy plugins: Bukkit still
 * constructs one normal JavaPlugin instance, but the obvious "deepest superclass before JavaPlugin"
 * scanner no longer points at the real logic class.
 */
public final class JavaPluginUnderlay implements Opcodes {
    private final ObfConfig config;
    private final Random random;
    private final NameGenerator pkgNames;
    private final NameGenerator classNames;
    private final NameGenerator memberNames;

    public JavaPluginUnderlay(ObfConfig config, long seed) {
        this.config = config;
        this.random = new Random(seed ^ 0x9E1F00DL);
        this.pkgNames = new NameGenerator(
                config.string("javaPluginUnderlay.packageStyle", config.string("renaming.packageStyle", "ascii")),
                config.integer("javaPluginUnderlay.packageNameMinLength", 8),
                config.integer("javaPluginUnderlay.packageNameMaxLength", 24),
                new Random(seed ^ 0x9E1F0ADEL));
        this.classNames = new NameGenerator(
                config.string("javaPluginUnderlay.classStyle", config.string("renaming.style", "ascii")),
                config.integer("javaPluginUnderlay.classNameMinLength", 24),
                config.integer("javaPluginUnderlay.classNameMaxLength", 64),
                new Random(seed ^ 0x9E1F0BEEFL));
        this.memberNames = new NameGenerator(
                config.string("javaPluginUnderlay.memberStyle", config.string("renaming.memberStyle", config.string("renaming.style", "ascii"))),
                config.integer("javaPluginUnderlay.memberNameMinLength", 10),
                config.integer("javaPluginUnderlay.memberNameMaxLength", 36),
                new Random(seed ^ 0x9E1F0C0DEL));
    }

    public Result apply(JarModel model, Map<String, byte[]> generatedClasses) {
        if (!config.enabled("javaPluginUnderlay", false)) return Result.disabled();
        if (model.pluginMainFqn == null || model.pluginMainFqn.isBlank()) return Result.disabled();
        String oldMain = model.pluginMainFqn.replace('.', '/');
        ClassEntry ce = model.classes.get(oldMain);
        if (ce == null) return Result.disabled();
        ClassNode main = ce.node;
        String oldSuper = main.superName;
        if (!"org/bukkit/plugin/java/JavaPlugin".equals(oldSuper)) {
            if (config.bool("javaPluginUnderlay.verbose", true)) {
                System.err.println("[mcshield] javaPluginUnderlay skipped: main does not directly extend JavaPlugin: " + oldMain + " -> " + oldSuper);
            }
            return Result.disabled();
        }
        if ((main.access & ACC_FINAL) != 0) main.access &= ~ACC_FINAL;

        int min = Math.max(1, config.integer("javaPluginUnderlay.chainLengthMin", 8));
        int max = Math.max(min, config.integer("javaPluginUnderlay.chainLengthMax", min));
        int count = min + (max == min ? 0 : random.nextInt(max - min + 1));
        List<String> owners = allocate(model, generatedClasses, count);

        // Build bottom-up: last generated class extends JavaPlugin, previous extends last, ...
        String parent = "org/bukkit/plugin/java/JavaPlugin";
        for (int i = owners.size() - 1; i >= 0; i--) {
            String owner = owners.get(i);
            generatedClasses.put(owner, generate(owner, parent, i, owners.size()));
            parent = owner;
        }

        // Real main now extends top underlay. Rewrite its no-arg super constructor call.
        String newSuper = owners.get(0);
        main.superName = newSuper;
        rewriteMainConstructorAndSuperCalls(main, oldSuper, newSuper);
        ce.transformed = true;
        return new Result(true, oldMain, newSuper, owners.get(owners.size() - 1), owners.size());
    }

    private List<String> allocate(JarModel model, Map<String, byte[]> generatedClasses, int count) {
        ArrayList<String> out = new ArrayList<>();
        String base = clean(config.string("javaPluginUnderlay.basePackage", config.string("renaming.basePackage", "z") + "/u"));
        int minDepth = Math.max(0, config.integer("javaPluginUnderlay.depthMin", 2));
        int maxDepth = Math.max(minDepth, config.integer("javaPluginUnderlay.depthMax", 6));
        for (int n = 0; n < count; n++) {
            for (int guard = 0; guard < 10000; guard++) {
                int depth = minDepth + (maxDepth == minDepth ? 0 : random.nextInt(maxDepth - minDepth + 1));
                StringBuilder sb = new StringBuilder(base);
                for (int i = 0; i < depth; i++) {
                    if (sb.length() > 0) sb.append('/');
                    sb.append(pkgNames.next());
                }
                if (sb.length() > 0) sb.append('/');
                sb.append(classNames.next());
                String owner = sb.toString();
                if (!model.classes.containsKey(owner) && !generatedClasses.containsKey(owner) && !out.contains(owner)) {
                    out.add(owner);
                    break;
                }
            }
        }
        return out;
    }

    private void rewriteMainConstructorAndSuperCalls(ClassNode cn, String oldSuper, String newSuper) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode mi && mi.getOpcode() == INVOKESPECIAL && oldSuper.equals(mi.owner)) {
                    // The constructor must target the new direct superclass. Lifecycle super calls also
                    // remain valid because underlay classes bridge to JavaPlugin.
                    mi.owner = newSuper;
                }
            }
        }
    }

    private byte[] generate(String owner, String superOwner, int index, int total) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = owner;
        cn.superName = superOwner;
        cn.sourceFile = config.string("javaPluginUnderlay.sourceFile", "entry.c");
        cn.sourceDebug = "SMAP\n" + cn.sourceFile + "\nC\n*S C\n*F\n+ 1 " + cn.sourceFile + "\n" + cn.sourceFile + "\n*L\n1#1,4096:1\n*E";

        addFields(cn, owner, Math.max(0, config.integer("javaPluginUnderlay.fieldCount", 28)));
        addConstructor(cn, owner, superOwner, index);
        addLifecycle(cn, owner, superOwner, index);
        addKnownMethods(cn, owner, index);
        int targetMethods = Math.max(cn.methods.size(), config.integer("javaPluginUnderlay.methodCount", 96));
        while (cn.methods.size() < targetMethods) addNoiseMethod(cn, owner, cn.methods.size() + index * 31);

        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private void addFields(ClassNode cn, String owner, int count) {
        String[] seeded = {
                "licenseManager", "pendingCards", "bankPaymentManager", "paymentGuiManager", "configManager",
                "databaseManager", "milestoneManager", "scheduler", "api", "pending", "pendingPayments",
                "paymentCache", "httpClient", "commands", "reloadToken", "lastCheck", "enabled", "service",
                "registry", "provider", "cardQueue", "bankQueue", "bossBarTask", "executor", "platform"
        };
        for (int i = 0; i < count; i++) {
            String name = i < seeded.length ? seeded[i] : memberNames.next();
            String desc = switch (i % 7) {
                case 0 -> "Ljava/util/Map;";
                case 1 -> "Ljava/lang/Object;";
                case 2 -> "Ljava/lang/String;";
                case 3 -> "Ljava/util/List;";
                case 4 -> "Ljava/util/Set;";
                case 5 -> "I";
                default -> "Z";
            };
            cn.fields.add(new FieldNode(ACC_PRIVATE, name, desc, null, null));
        }
    }

    private void addConstructor(ClassNode cn, String owner, String superOwner, int id) {
        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "<init>", "()V", false));
        for (int i = 0; i < cn.fields.size(); i++) {
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
                case "Ljava/util/Set;" -> {
                    init.instructions.add(new TypeInsnNode(NEW, "java/util/HashSet"));
                    init.instructions.add(new InsnNode(DUP));
                    init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/util/HashSet", "<init>", "()V", false));
                }
                case "Ljava/lang/String;" -> init.instructions.add(new LdcInsnNode("stage-" + Integer.toHexString(id ^ i ^ owner.hashCode())));
                case "I" -> pushInt(init, id * 131 + i);
                case "Z" -> init.instructions.add(((id + i) & 1) == 0 ? new InsnNode(ICONST_1) : new InsnNode(ICONST_0));
                default -> init.instructions.add(new InsnNode(ACONST_NULL));
            }
            init.instructions.add(new FieldInsnNode(PUTFIELD, owner, fn.name, fn.desc));
        }
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);
    }

    private void addLifecycle(ClassNode cn, String owner, String superOwner, int id) {
        cn.methods.add(lifecycleVoid("onLoad", superOwner, id));
        cn.methods.add(lifecycleVoid("onEnable", superOwner, id ^ 0x11));
        cn.methods.add(lifecycleVoid("onDisable", superOwner, id ^ 0x22));

        MethodNode cmd = new MethodNode(ACC_PUBLIC, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", null, null);
        cmd.instructions.add(new VarInsnNode(ALOAD, 0));
        cmd.instructions.add(new VarInsnNode(ALOAD, 1));
        cmd.instructions.add(new VarInsnNode(ALOAD, 2));
        cmd.instructions.add(new VarInsnNode(ALOAD, 3));
        cmd.instructions.add(new VarInsnNode(ALOAD, 4));
        cmd.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", false));
        cmd.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(cmd);

        MethodNode tab = new MethodNode(ACC_PUBLIC, "onTabComplete", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;", null, null);
        tab.instructions.add(new VarInsnNode(ALOAD, 0));
        tab.instructions.add(new VarInsnNode(ALOAD, 1));
        tab.instructions.add(new VarInsnNode(ALOAD, 2));
        tab.instructions.add(new VarInsnNode(ALOAD, 3));
        tab.instructions.add(new VarInsnNode(ALOAD, 4));
        tab.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onTabComplete", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;", false));
        tab.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(tab);
    }

    private MethodNode lifecycleVoid(String name, String superOwner, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()V", null, null);
        pushInt(m, id ^ 0x517cc0de);
        pushInt(m, Integer.rotateLeft(id, 5));
        m.instructions.add(new InsnNode(IXOR));
        m.instructions.add(new InsnNode(POP));
        m.instructions.add(new VarInsnNode(ALOAD, 0));
        m.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, name, "()V", false));
        m.instructions.add(new InsnNode(RETURN));
        return m;
    }

    private void addKnownMethods(ClassNode cn, String owner, int id) {
        addVoid(cn, owner, "reloadPlugin", id);
        addBool(cn, owner, "checkLicense", id ^ 7);
        addObj(cn, owner, "createHttpClient", id ^ 11);
        addBool(cn, owner, "processSuccessPayment", id ^ 13);
        addBool(cn, owner, "processManualTopup", id ^ 17);
        addObj(cn, owner, "handleCardResponse", id ^ 19);
        addVoid(cn, owner, "giveCardReward", id ^ 23);
        addObj(cn, owner, "getPendingCards", id ^ 29);
        addObj(cn, owner, "getBankPaymentManager", id ^ 31);
        addVoid(cn, owner, "startBossBarTask", id ^ 37);
        addVoid(cn, owner, "runTimerAsync", id ^ 41);
    }

    private void addNoiseMethod(ClassNode cn, String owner, int id) {
        String name = memberNames.next();
        switch (Math.floorMod(id, 5)) {
            case 0 -> addVoid(cn, owner, name, id);
            case 1 -> addBool(cn, owner, name, id);
            case 2 -> addObj(cn, owner, name, id);
            case 3 -> addInt(cn, owner, name, id);
            default -> addString(cn, owner, name, id);
        }
    }

    private void addVoid(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()V", null, null);
        opaque(m, owner, id);
        m.instructions.add(new InsnNode(RETURN));
        cn.methods.add(m);
    }
    private void addBool(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()Z", null, null);
        opaque(m, owner, id);
        m.instructions.add((id & 1) == 0 ? new InsnNode(ICONST_0) : new InsnNode(ICONST_1));
        m.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(m);
    }
    private void addInt(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()I", null, null);
        pushInt(m, id ^ owner.hashCode());
        m.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(m);
    }
    private void addObj(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()Ljava/lang/Object;", null, null);
        if (!cn.fields.isEmpty()) {
            FieldNode fn = (FieldNode) cn.fields.get(Math.floorMod(id, cn.fields.size()));
            if (fn.desc.startsWith("L") || fn.desc.startsWith("[")) {
                m.instructions.add(new VarInsnNode(ALOAD, 0));
                m.instructions.add(new FieldInsnNode(GETFIELD, owner, fn.name, fn.desc));
            } else m.instructions.add(new InsnNode(ACONST_NULL));
        } else m.instructions.add(new InsnNode(ACONST_NULL));
        m.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(m);
    }
    private void addString(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, "()Ljava/lang/String;", null, null);
        m.instructions.add(new LdcInsnNode("node-" + Integer.toHexString(id ^ owner.hashCode())));
        m.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(m);
    }

    private void opaque(MethodNode m, String owner, int id) {
        pushInt(m, id ^ owner.hashCode());
        pushInt(m, Integer.rotateLeft(id, 9) ^ owner.length());
        m.instructions.add(new InsnNode(IXOR));
        m.instructions.add(new InsnNode(POP));
    }

    private void pushInt(MethodNode m, int v) {
        if (v >= -1 && v <= 5) m.instructions.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) m.instructions.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) m.instructions.add(new IntInsnNode(SIPUSH, v));
        else m.instructions.add(new LdcInsnNode(v));
    }

    private static String clean(String p) {
        String out = p == null ? "" : p.replace('.', '/').trim();
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length()-1);
        return out;
    }

    public record Result(boolean enabled, String mainOwner, String topUnderlay, String bottomUnderlay, int chainLength) {
        static Result disabled() { return new Result(false, null, null, null, 0); }
    }
}
