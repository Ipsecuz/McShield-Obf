package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.NameGenerator;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.FieldInsnNode;
import jdk.internal.org.objectweb.asm.tree.FieldNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Hides the real JavaPlugin implementation behind a configurable chain of generated subclasses.
 *
 * Proxy camouflage: proxy classes are no longer empty constructor-only shells.
 * Each proxy can contain lifecycle bridge methods that still call super, plus fake fields and
 * plausible plugin-looking overloads. A script following plugin.yml -> superclass can no longer
 * stop at "first class with onEnable/checkLicense" and get the real implementation directly.
 */
public final class EntryPointProxy implements Opcodes {
    private final ObfConfig config;
    private final Random random;
    private final NameGenerator pkgNames;
    private final NameGenerator classNames;
    private final NameGenerator memberNames;

    public EntryPointProxy(ObfConfig config, long seed) {
        this.config = config;
        this.random = new Random(seed ^ 0xE771FACEB00BL);
        this.pkgNames = new NameGenerator(
                config.string("entrypointProxy.packageStyle", config.string("renaming.packageStyle", "spoof")),
                config.integer("entrypointProxy.packageNameMinLength", config.integer("renaming.packageNameMinLength", 0)),
                config.integer("entrypointProxy.packageNameMaxLength", config.integer("renaming.packageNameMaxLength", 0)),
                new Random(seed ^ 0xE771A11CL)
        );
        this.classNames = new NameGenerator(
                config.string("entrypointProxy.classStyle", config.string("renaming.style", "il")),
                config.integer("entrypointProxy.classNameMinLength", config.integer("renaming.classNameMinLength", 0)),
                config.integer("entrypointProxy.classNameMaxLength", config.integer("renaming.classNameMaxLength", 0)),
                new Random(seed ^ 0xE771C1A55L)
        );
        this.memberNames = new NameGenerator(
                config.string("entrypointProxy.memberStyle", config.string("renaming.memberStyle", config.string("renaming.style", "ascii"))),
                config.integer("entrypointProxy.memberNameMinLength", config.integer("renaming.memberNameMinLength", 12)),
                config.integer("entrypointProxy.memberNameMaxLength", config.integer("renaming.memberNameMaxLength", 34)),
                new Random(seed ^ 0xE771D00DL)
        );
    }

    public Result apply(JarModel model, MappingContext mapping, Map<String, byte[]> generatedClasses) {
        if (!config.enabled("entrypointProxy", false)) return Result.disabled();
        if (model.pluginMainFqn == null || model.pluginMainFqn.isBlank()) return Result.disabled();

        String oldMain = model.pluginMainFqn.replace('.', '/');
        ClassEntry mainEntry = model.classes.get(oldMain);
        if (mainEntry == null) {
            System.err.println("[mcshield] entrypointProxy skipped: main class not found in input model: " + oldMain);
            return Result.disabled();
        }

        MethodNode init = noArgConstructor(mainEntry.node);
        if (init == null) {
            System.err.println("[mcshield] entrypointProxy skipped: main class has no no-arg constructor: " + oldMain);
            return Result.disabled();
        }
        if ((init.access & ACC_PRIVATE) != 0) {
            System.err.println("[mcshield] entrypointProxy skipped: main no-arg constructor is private: " + oldMain);
            return Result.disabled();
        }

        mainEntry.node.access &= ~ACC_FINAL;
        // Important when frames.mode=preserve or JarIO may reuse original class bytes.
        // Without this, Kotlin/final plugin main classes stay final in the output jar,
        // while the generated entrypoint proxy tries to extend them, causing:
        // IncompatibleClassChangeError: cannot inherit from final class.
        mainEntry.transformed = true;

        List<String> chain = allocateProxyChain(model, mapping, generatedClasses);
        String parent = oldMain;
        String yamlEntry = null;

        for (int i = 0; i < chain.size(); i++) {
            String proxy = chain.get(i);
            byte[] bytes = generateProxy(proxy, parent, i, chain.size());
            generatedClasses.put(proxy, bytes);
            parent = proxy;
            yamlEntry = proxy;
        }

        Map<String, String> yaml = new LinkedHashMap<>(mapping.fullMap());
        yaml.put(oldMain, yamlEntry);
        return new Result(true, oldMain, yamlEntry, yaml, chain.size());
    }

    private MethodNode noArgConstructor(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (mn.name.equals("<init>") && mn.desc.equals("()V")) return mn;
        }
        return null;
    }

    private List<String> allocateProxyChain(JarModel model, MappingContext mapping, Map<String, byte[]> generatedClasses) {
        int legacyMin = config.integer("entrypointProxy.chainDepthMin", config.integer("entrypointProxy.chainDepth", 1));
        int minChain = Math.max(1, config.integer("entrypointProxy.chainLengthMin", legacyMin));
        int maxChain = Math.max(minChain, config.integer("entrypointProxy.chainLengthMax", config.integer("entrypointProxy.chainDepthMax", minChain)));
        int count = minChain + (maxChain == minChain ? 0 : random.nextInt(maxChain - minChain + 1));

        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            out.add(nextProxyOwner(model, mapping, generatedClasses, out));
        }
        return out;
    }

    private String nextProxyOwner(JarModel model, MappingContext mapping, Map<String, byte[]> generatedClasses, List<String> allocated) {
        String base = NameGenerator.cleanPackage(config.string("entrypointProxy.basePackage", config.string("renaming.basePackage", "x")));
        int min = Math.max(0, config.integer("entrypointProxy.packageDepthMin", config.integer("renaming.packageDepthMin", 8)));
        int max = Math.max(min, config.integer("entrypointProxy.packageDepthMax", Math.max(min, config.integer("renaming.packageDepthMax", min))));

        int guard = 0;
        while (guard++ < 10000) {
            int depth = min + (max == min ? 0 : random.nextInt(max - min + 1));
            StringBuilder sb = new StringBuilder(base);
            for (int i = 0; i < depth; i++) {
                if (sb.length() > 0) sb.append('/');
                sb.append(pkgNames.next());
            }
            if (sb.length() > 0) sb.append('/');
            sb.append(classNames.next());

            String owner = sb.toString();
            if (!model.classes.containsKey(owner)
                    && !mapping.classMap.containsValue(owner)
                    && !generatedClasses.containsKey(owner)
                    && !allocated.contains(owner)) {
                return owner;
            }
        }
        throw new IllegalStateException("Cannot allocate unique entrypoint proxy name");
    }

    private byte[] generateProxy(String proxyOwner, String superOwner, int index, int total) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        // Do not make proxy final. A chainLength > 1 means the next proxy must extend this proxy.
        cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = proxyOwner;
        cn.superName = superOwner;
        cn.sourceFile = config.string("entrypointProxy.sourceFile", "native_entry.c");
        cn.sourceDebug = "SMAP\n" + cn.sourceFile + "\nC\n*S C\n*F\n+ 1 " + cn.sourceFile + "\n" + cn.sourceFile + "\n*L\n1#1,4096:1\n*E";

        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);

        if (config.bool("entrypointProxy.camo", true)) {
            addCamouflage(cn, proxyOwner, superOwner, index, total);
        }

        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private void addCamouflage(ClassNode cn, String owner, String superOwner, int index, int total) {
        int fields = Math.max(0, config.integer("entrypointProxy.camoFields", 10));
        int methods = Math.max(0, config.integer("entrypointProxy.camoMethods", 18));

        addCamoFields(cn, fields, index);
        addLifecycleBridges(cn, superOwner, index);
        addKnownNameNoise(cn, owner, index);

        for (int i = 0; i < methods; i++) {
            int kind = i % 5;
            String n = memberNames.next();
            if (kind == 0) addVoidNoise(cn, owner, n, index + i);
            else if (kind == 1) addBoolNoise(cn, owner, n, index + i);
            else if (kind == 2) addObjectNoise(cn, owner, n, index + i);
            else if (kind == 3) addIntNoise(cn, owner, n, index + i);
            else addStringNoise(cn, n, index + i);
        }
    }

    private void addCamoFields(ClassNode cn, int fields, int index) {
        String[] seeded = {
                "licenseManager", "pendingCards", "bankPaymentManager", "paymentGuiManager", "pending",
                "api", "scheduler", "registry", "reloadToken", "httpClient"
        };

        for (int i = 0; i < fields; i++) {
            String name = i < seeded.length ? seeded[i] : memberNames.next();
            String desc = switch (i % 6) {
                case 0 -> "Ljava/util/Map;";
                case 1 -> "Ljava/lang/Object;";
                case 2 -> "Ljava/lang/String;";
                case 3 -> "I";
                case 4 -> "Z";
                default -> "Ljava/util/List;";
            };
            cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_SYNTHETIC, name, desc, null, null));
        }
    }

    private void addLifecycleBridges(ClassNode cn, String superOwner, int index) {
        MethodNode onLoad = new MethodNode(ACC_PUBLIC, "onLoad", "()V", null, null);
        addNoise(onLoad, index);
        onLoad.instructions.add(new VarInsnNode(ALOAD, 0));
        onLoad.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onLoad", "()V", false));
        onLoad.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onLoad);

        MethodNode onEnable = new MethodNode(ACC_PUBLIC, "onEnable", "()V", null, null);
        addNoise(onEnable, index ^ 0x11);
        onEnable.instructions.add(new VarInsnNode(ALOAD, 0));
        onEnable.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onEnable", "()V", false));
        onEnable.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onEnable);

        MethodNode onDisable = new MethodNode(ACC_PUBLIC, "onDisable", "()V", null, null);
        addNoise(onDisable, index ^ 0x22);
        onDisable.instructions.add(new VarInsnNode(ALOAD, 0));
        onDisable.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onDisable", "()V", false));
        onDisable.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onDisable);

        MethodNode onCommand = new MethodNode(
                ACC_PUBLIC,
                "onCommand",
                "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z",
                null,
                null
        );
        addNoise(onCommand, index ^ 0x33);
        onCommand.instructions.add(new VarInsnNode(ALOAD, 0));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 1));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 2));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 3));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 4));
        onCommand.instructions.add(new MethodInsnNode(
                INVOKESPECIAL,
                superOwner,
                "onCommand",
                "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z",
                false
        ));
        onCommand.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(onCommand);

        MethodNode onTab = new MethodNode(
                ACC_PUBLIC,
                "onTabComplete",
                "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;",
                null,
                null
        );
        addNoise(onTab, index ^ 0x44);
        onTab.instructions.add(new VarInsnNode(ALOAD, 0));
        onTab.instructions.add(new VarInsnNode(ALOAD, 1));
        onTab.instructions.add(new VarInsnNode(ALOAD, 2));
        onTab.instructions.add(new VarInsnNode(ALOAD, 3));
        onTab.instructions.add(new VarInsnNode(ALOAD, 4));
        onTab.instructions.add(new MethodInsnNode(
                INVOKESPECIAL,
                superOwner,
                "onTabComplete",
                "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;",
                false
        ));
        onTab.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(onTab);
    }

    private void addKnownNameNoise(ClassNode cn, String owner, int id) {
        // Overloaded signatures prevent overriding real internals, but confuse name-based scans.
        addBoolNoise(cn, owner, "checkLicense", id);
        addObjectNoise(cn, owner, "createHttpClient", id ^ 1);
        addBoolNoise(cn, owner, "processSuccessPayment", id ^ 2);
        addBoolNoise(cn, owner, "processManualTopup", id ^ 3);
        addObjectNoise(cn, owner, "handleCardResponse", id ^ 4);
        addVoidNoise(cn, owner, "giveCardReward", id ^ 5);
        addObjectNoise(cn, owner, "getPendingCards", id ^ 6);
        addVoidNoise(cn, owner, "startBossBarTask", id ^ 7);
        addVoidNoise(cn, owner, "reloadPlugin", id ^ 8);
    }

    private void addVoidNoise(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, "(I)V", null, null);
        addNoise(m, id);
        m.instructions.add(new InsnNode(RETURN));
        cn.methods.add(m);
    }

    private void addBoolNoise(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, "(Ljava/lang/Object;I)Z", null, null);
        addNoise(m, id);
        m.instructions.add((id & 1) == 0 ? new InsnNode(ICONST_0) : new InsnNode(ICONST_1));
        m.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(m);
    }

    private void addObjectNoise(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, "(Ljava/lang/Object;)Ljava/lang/Object;", null, null);
        if (!cn.fields.isEmpty()) {
            FieldNode fn = cn.fields.get(Math.floorMod(id, cn.fields.size()));
            if (fn.desc.startsWith("L") || fn.desc.startsWith("[")) {
                m.instructions.add(new VarInsnNode(ALOAD, 0));
                m.instructions.add(new FieldInsnNode(GETFIELD, owner, fn.name, fn.desc));
            } else {
                m.instructions.add(new InsnNode(ACONST_NULL));
            }
        } else {
            m.instructions.add(new InsnNode(ACONST_NULL));
        }
        m.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(m);
    }

    private void addIntNoise(ClassNode cn, String owner, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, "()I", null, null);
        pushInt(m, id * 31 + owner.length());
        m.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(m);
    }

    private void addStringNoise(ClassNode cn, String name, int id) {
        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, "()Ljava/lang/String;", null, null);
        m.instructions.add(new LdcInsnNode("route-" + Integer.toHexString(id ^ name.hashCode())));
        m.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(m);
    }

    private void addNoise(MethodNode m, int id) {
        pushInt(m, id ^ 0x5a5a5a5a);
        pushInt(m, Integer.rotateLeft(id, 9));
        m.instructions.add(new InsnNode(IXOR));
        m.instructions.add(new InsnNode(POP));
    }

    private void pushInt(MethodNode m, int v) {
        if (v >= -1 && v <= 5) {
            m.instructions.add(new InsnNode(ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            m.instructions.add(new IntInsnNode(BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            m.instructions.add(new IntInsnNode(SIPUSH, v));
        } else {
            m.instructions.add(new LdcInsnNode(v));
        }
    }

    public record Result(boolean enabled, String originalMain, String proxyOwner, Map<String, String> yamlRemap, int chainDepth) {
        static Result disabled() {
            return new Result(false, null, null, null, 0);
        }
    }
}
