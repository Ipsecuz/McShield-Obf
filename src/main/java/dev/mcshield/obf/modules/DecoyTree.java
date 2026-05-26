package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.util.Bytecode;
import dev.mcshield.obf.util.NameGenerator;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.JumpInsnNode;
import jdk.internal.org.objectweb.asm.tree.LabelNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/** Generates harmless nested classes/resources to make archive browsing noisy without creating a zip bomb. */
public final class DecoyTree implements Opcodes {
    private final ObfConfig config;
    private final Random random;
    private final NameGenerator pkgNames;
    private final NameGenerator classNames;

    public DecoyTree(ObfConfig config, long seed) {
        this.config = config;
        this.random = new Random(seed ^ 0xD3C0E771L);
        this.pkgNames = new NameGenerator(
                config.string("decoyTree.packageStyle", config.string("renaming.packageStyle", "spoof")),
                config.integer("decoyTree.packageNameMinLength", config.integer("renaming.packageNameMinLength", 0)),
                config.integer("decoyTree.packageNameMaxLength", config.integer("renaming.packageNameMaxLength", 0)),
                new Random(seed ^ 0xD3C0C0DEL));
        this.classNames = new NameGenerator(
                config.string("decoyTree.classStyle", config.string("renaming.style", "il")),
                config.integer("decoyTree.classNameMinLength", config.integer("renaming.classNameMinLength", 0)),
                config.integer("decoyTree.classNameMaxLength", config.integer("renaming.classNameMaxLength", 0)),
                new Random(seed ^ 0xD3C0C1A55L));
    }

    public Map<String, byte[]> classes() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.enabled("decoyTree", false)) return out;
        int count = safeCount(config.integer("decoyTree.classes", 48), 0, 500);
        for (int i = 0; i < count; i++) {
            String owner = nextOwner(i);
            out.put(owner, makeClass(owner, i));
        }
        return out;
    }

    public Map<String, byte[]> resources() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.enabled("decoyTree", false) || !config.bool("decoyTree.resources", true)) return out;
        int count = safeCount(config.integer("decoyTree.resourceFiles", 32), 0, 300);
        for (int i = 0; i < count; i++) {
            String path = nextOwner(i + 8192);
            String ext = switch (Math.floorMod(i, 5)) {
                case 0 -> ".c";
                case 1 -> ".h";
                case 2 -> ".map";
                case 3 -> ".yml";
                default -> ".dat";
            };
            out.put(path + ext, decoyResource(i).getBytes(StandardCharsets.UTF_8));
        }
        return out;
    }

    private int safeCount(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private String nextOwner(int salt) {
        String base = NameGenerator.cleanPackage(config.string("decoyTree.basePackage", config.string("renaming.basePackage", "x")));
        int min = safeCount(config.integer("decoyTree.depthMin", 12), 0, 180);
        int max = safeCount(config.integer("decoyTree.depthMax", 40), min, 180);
        int depth = min + (max == min ? 0 : random.nextInt(max - min + 1));
        StringBuilder sb = new StringBuilder(base);
        for (int i = 0; i < depth; i++) {
            if (sb.length() > 0) sb.append('/');
            sb.append(pkgNames.next());
        }
        if (sb.length() > 0) sb.append('/');
        sb.append(classNames.next());
        if (salt != 0) sb.append(classNames.next());
        return sb.toString();
    }

    private byte[] makeClass(String owner, int id) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_FINAL | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = owner;
        cn.superName = "java/lang/Object";
        cn.sourceFile = config.string("decoyTree.sourceFile", "native_blob.c");
        cn.sourceDebug = "SMAP\n" + cn.sourceFile + "\nC\n*S C\n*F\n+ 1 " + cn.sourceFile + "\n" + cn.sourceFile + "\n*L\n1#1,8192:1\n*E";

        MethodNode init = new MethodNode(ACC_PRIVATE, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);

        int methods = safeCount(config.integer("decoyTree.methodsPerClass", 2), 0, 16);
        for (int i = 0; i < methods; i++) {
            cn.methods.add(decoyMethod(id, i));
        }

        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private MethodNode decoyMethod(int id, int m) {
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC, classNames.next(), "(I)I", null, null);
        LabelNode ret = new LabelNode();
        mn.instructions.add(new VarInsnNode(ILOAD, 0));
        mn.instructions.add(Bytecode.pushInt((id + 1) * (m + 17)));
        mn.instructions.add(new InsnNode(IXOR));
        mn.instructions.add(new VarInsnNode(ISTORE, 1));
        mn.instructions.add(new VarInsnNode(ILOAD, 1));
        mn.instructions.add(new IntInsnNode(BIPUSH, random.nextInt(120) + 1));
        mn.instructions.add(new InsnNode(IAND));
        mn.instructions.add(new JumpInsnNode(IFEQ, ret));
        mn.instructions.add(new VarInsnNode(ILOAD, 1));
        mn.instructions.add(Bytecode.pushInt(random.nextInt()));
        mn.instructions.add(new InsnNode(IADD));
        mn.instructions.add(new VarInsnNode(ISTORE, 1));
        mn.instructions.add(ret);
        mn.instructions.add(new VarInsnNode(ILOAD, 1));
        mn.instructions.add(new InsnNode(IRETURN));
        return mn;
    }

    private String decoyResource(int i) {
        return "/* generated native decoy: do not edit */\n"
                + "#define MC_SHIELD_SLOT " + i + "\n"
                + "static unsigned long checkpoint_" + Integer.toHexString(random.nextInt()) + "(unsigned long x) {\n"
                + "  return (x ^ 0x" + Integer.toHexString(random.nextInt()) + "UL) + 0x" + Integer.toHexString(random.nextInt()) + "UL;\n"
                + "}\n";
    }
}
