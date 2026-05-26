package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.Bytecode;
import dev.mcshield.obf.util.NameGenerator;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.Type;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.InsnList;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.TypeInsnNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ReferenceReflection implements Opcodes {
    public static final String BASE_REF_OWNER = "dev/mcshield/obf/runtime/Ref";

    private final ObfConfig config;
    private final String refOwner;
    private final String stringsOwner;
    private final String wrapperOwner;
    private final NameGenerator wrapperNames;
    private final Set<String> usedWrapperNames = new HashSet<>();
    private final boolean strongStrings;
    private final String stringMode;

    public ReferenceReflection(ObfConfig config, String refOwner, String stringsOwner, String wrapperOwner) {
        this.config = config;
        this.refOwner = refOwner;
        this.stringsOwner = stringsOwner;
        this.wrapperOwner = wrapperOwner;
        this.wrapperNames = new NameGenerator(config.string("referenceReflection.wrapperNameStyle", config.string("referenceReflection.wrapperStyle", config.string("renaming.memberStyle", "ascii"))));
        this.strongStrings = StringEncryptor.strongMode(config);
        this.stringMode = config.string("stringEncryption.mode", strongStrings ? "array" : "direct");
    }

    public ReferenceReflection(ObfConfig config, String refOwner, String stringsOwner, String wrapperOwner, long seed) {
        this(config, refOwner, stringsOwner, wrapperOwner);
    }

    public byte[] apply(JarModel model) {
        if (!config.enabled("referenceReflection", true)) return null;
        Map<Target, String> wrappers = new LinkedHashMap<>();
        int changed = 0;
        for (ClassEntry ce : model.classes.values()) {
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode mi)) continue;
                    int opcode = mi.getOpcode();
                    if (opcode == INVOKESTATIC && shouldReflectStatic(mi)) {
                        Target t = Target.staticCall(mi.owner, mi.name, mi.desc);
                        String wrapper = wrappers.computeIfAbsent(t, x -> nextWrapperName());
                        mi.owner = wrapperOwner;
                        mi.name = wrapper;
                        mi.itf = false;
                        changed++;
                    } else if ((opcode == INVOKEVIRTUAL || opcode == INVOKEINTERFACE) && shouldReflectInstance(mi)) {
                        Target t = Target.instanceCall(mi.owner, mi.name, mi.desc);
                        String wrapper = wrappers.computeIfAbsent(t, x -> nextWrapperName());
                        mi.setOpcode(INVOKESTATIC);
                        mi.owner = wrapperOwner;
                        mi.name = wrapper;
                        mi.desc = t.wrapperDesc();
                        mi.itf = false;
                        changed++;
                    }
                }
            }
        }
        if (changed == 0) return null;
        System.out.println("[mcshield] referenceReflection rewrote " + changed + " API calls");
        return generateWrapper(wrappers);
    }

    private boolean shouldReflectStatic(MethodInsnNode mi) {
        List<String> targets = config.list("referenceReflection.targets");
        if (!targets.isEmpty()) return matchesAny(mi, targets);
        if (!mi.owner.equals("org/bukkit/Bukkit")) return false;
        return switch (mi.name) {
            case "getPlayer", "getWorld", "getServer", "getPluginManager", "getScheduler", "getOnlinePlayers", "broadcastMessage" -> true;
            default -> false;
        };
    }

    private boolean shouldReflectInstance(MethodInsnNode mi) {
        if (!config.bool("referenceReflection.instance", true)) return false;
        List<String> targets = config.list("referenceReflection.instanceTargets");
        if (!targets.isEmpty()) return matchesAny(mi, targets);
        if (!config.list("referenceReflection.instanceMethodNames").isEmpty()) {
            return config.list("referenceReflection.instanceMethodNames").contains(mi.name);
        }
        return switch (mi.name) {
            // Startup/bootstrap calls that often reveal plugin command names or API dependency edges.
            case "getCommand", "setExecutor", "setTabCompleter", "registerEvents", "getPluginManager", "getScheduler", "getConfig", "saveDefaultConfig" -> true;
            default -> false;
        };
    }

    private boolean matchesAny(MethodInsnNode mi, List<String> patterns) {
        String internalKey = mi.owner + "." + mi.name + mi.desc;
        String fqnKey = mi.owner.replace('/', '.') + "." + mi.name + mi.desc;
        String nameDesc = mi.name + mi.desc;
        return Wildcard.any(internalKey, patterns) || Wildcard.any(fqnKey, patterns) || Wildcard.any(nameDesc, patterns);
    }

    private String nextWrapperName() {
        String n;
        do {
            n = wrapperNames.next();
        } while (!usedWrapperNames.add(n) || n.equals("<init>") || n.equals("<clinit>"));
        return n;
    }

    private byte[] generateWrapper(Map<Target, String> wrappers) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC;
        cn.name = wrapperOwner;
        cn.superName = "java/lang/Object";

        MethodNode init = new MethodNode(ACC_PRIVATE, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);

        for (Map.Entry<Target, String> e : wrappers.entrySet()) {
            cn.methods.add(e.getKey().isStatic ? staticWrapper(e.getValue(), e.getKey()) : instanceWrapper(e.getValue(), e.getKey()));
        }
        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private MethodNode staticWrapper(String name, Target t) {
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC, name, t.desc, null, null);
        InsnList il = mn.instructions;
        addEncryptedString(il, t.owner.replace('/', '.'));
        addEncryptedString(il, t.name);
        Type[] args = Type.getArgumentTypes(t.desc);
        addTypesAndArgs(il, args, 0);
        il.add(new MethodInsnNode(INVOKESTATIC, refOwner, "s", "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        Type ret = Type.getReturnType(t.desc);
        Bytecode.unboxOrCast(il, ret);
        il.add(new InsnNode(Bytecode.returnOpcode(ret)));
        return mn;
    }

    private MethodNode instanceWrapper(String name, Target t) {
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC, name, t.wrapperDesc(), null, null);
        InsnList il = mn.instructions;
        il.add(new VarInsnNode(ALOAD, 0));
        addEncryptedString(il, t.name);
        Type[] args = Type.getArgumentTypes(t.desc);
        addTypesAndArgs(il, args, 1);
        il.add(new MethodInsnNode(INVOKESTATIC, refOwner, "v", "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        Type ret = Type.getReturnType(t.desc);
        Bytecode.unboxOrCast(il, ret);
        il.add(new InsnNode(Bytecode.returnOpcode(ret)));
        return mn;
    }

    private void addTypesAndArgs(InsnList il, Type[] args, int firstLocal) {
        il.add(Bytecode.pushInt(args.length));
        il.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        for (int i = 0; i < args.length; i++) {
            il.add(new InsnNode(DUP));
            il.add(Bytecode.pushInt(i));
            Bytecode.addClassLiteral(il, args[i]);
            il.add(new InsnNode(AASTORE));
        }

        il.add(Bytecode.pushInt(args.length));
        il.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
        int local = firstLocal;
        for (int i = 0; i < args.length; i++) {
            Type a = args[i];
            il.add(new InsnNode(DUP));
            il.add(Bytecode.pushInt(i));
            il.add(new VarInsnNode(Bytecode.loadOpcode(a), local));
            Bytecode.box(il, a);
            il.add(new InsnNode(AASTORE));
            local += Bytecode.sizeOf(a);
        }
    }

    private void addEncryptedString(InsnList il, String plain) {
        int keyA = (plain.hashCode() * 31) | 1;
        int keyB = (plain.hashCode() ^ 0x6D2B79F5) | 1;
        StringEncryptor.emitEncryptedString(il, plain, keyA, keyB, stringsOwner, stringMode, nextWrapperName());
    }

    private record Target(boolean isStatic, String owner, String name, String desc) {
        static Target staticCall(String owner, String name, String desc) { return new Target(true, owner, name, desc); }
        static Target instanceCall(String owner, String name, String desc) { return new Target(false, owner, name, desc); }
        String wrapperDesc() {
            Type[] args = Type.getArgumentTypes(desc);
            Type[] withReceiver = new Type[args.length + 1];
            withReceiver[0] = Type.getType(Object.class);
            System.arraycopy(args, 0, withReceiver, 1, args.length);
            return Type.getMethodDescriptor(Type.getReturnType(desc), withReceiver);
        }
    }
}
