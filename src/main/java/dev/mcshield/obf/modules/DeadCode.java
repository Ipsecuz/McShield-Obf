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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

public final class DeadCode implements Opcodes {
    private final ObfConfig config;
    private final Random random;
    private final NameGenerator names;

    public DeadCode(ObfConfig config, long seed) {
        this.config = config;
        this.random = new Random(seed ^ 0xDEAD_C0DEL);
        this.names = new NameGenerator(config.string("deadCode.style", config.string("renaming.style", "ascii")));
    }

    public Map<String, byte[]> generate() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.enabled("deadCode", true)) return out;
        int count = Math.max(0, config.integer("deadCode.classes", 8));
        String pkg = config.string("deadCode.package", "x/noise").replace('.', '/');
        boolean tree = config.bool("deadCode.packageTree.enabled", config.bool("renaming.packageTree.enabled", false));
        int minDepth = tree ? config.integer("deadCode.packageTree.minDepth", 1) : 0;
        int maxDepth = tree ? config.integer("deadCode.packageTree.maxDepth", Math.max(1, minDepth)) : 0;
        for (int i = 0; i < count; i++) {
            String name = tree ? names.nextInternalClass(pkg, minDepth, maxDepth, random) : pkg + "/" + names.next();
            out.put(name, generateClass(name));
        }
        return out;
    }

    private byte[] generateClass(String internalName) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC;
        cn.name = internalName;
        cn.superName = "java/lang/Object";
        MethodNode init = new MethodNode(ACC_PRIVATE, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);
        int methods = Math.max(1, config.integer("deadCode.methodsPerClass", 3));
        String methodPrefix = (config.enabled("fakeC", false) || config.bool("antiDecompile.fakeCLanguage", false)) ? "sub_" : "n";
        for (int i = 0; i < methods; i++) cn.methods.add(noiseMethod(methodPrefix + Integer.toHexString(random.nextInt())));
        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private MethodNode noiseMethod(String name) {
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC, name, "(I)I", null, null);
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        int mask = random.nextInt();
        mn.instructions.add(new VarInsnNode(ILOAD, 0));
        mn.instructions.add(Bytecode.pushInt(mask));
        mn.instructions.add(new InsnNode(IXOR));
        mn.instructions.add(new VarInsnNode(ISTORE, 1));
        mn.instructions.add(Bytecode.pushInt(0));
        mn.instructions.add(new VarInsnNode(ISTORE, 2));
        mn.instructions.add(loop);
        mn.instructions.add(new VarInsnNode(ILOAD, 2));
        mn.instructions.add(new IntInsnNode(BIPUSH, 3));
        mn.instructions.add(new JumpInsnNode(IF_ICMPGE, end));
        mn.instructions.add(new VarInsnNode(ILOAD, 1));
        mn.instructions.add(new VarInsnNode(ILOAD, 2));
        mn.instructions.add(new InsnNode(IADD));
        mn.instructions.add(new VarInsnNode(ISTORE, 1));
        mn.instructions.add(new VarInsnNode(ILOAD, 2));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new InsnNode(IADD));
        mn.instructions.add(new VarInsnNode(ISTORE, 2));
        mn.instructions.add(new JumpInsnNode(GOTO, loop));
        mn.instructions.add(end);
        mn.instructions.add(new VarInsnNode(ILOAD, 1));
        mn.instructions.add(Bytecode.pushInt(mask));
        mn.instructions.add(new InsnNode(IXOR));
        mn.instructions.add(new InsnNode(IRETURN));
        return mn;
    }
}
