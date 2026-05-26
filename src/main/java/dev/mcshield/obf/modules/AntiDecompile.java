package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.LabelNode;
import jdk.internal.org.objectweb.asm.tree.LineNumberNode;
import jdk.internal.org.objectweb.asm.tree.LocalVariableNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.TryCatchBlockNode;

import java.util.ArrayList;

public final class AntiDecompile implements Opcodes {
    private final ObfConfig config;

    public AntiDecompile(ObfConfig config) {
        this.config = config;
    }

    public int apply(JarModel model) {
        if (!config.enabled("antiDecompile", true)) return 0;
        boolean fakeC = config.enabled("fakeC", false) || config.bool("antiDecompile.fakeCLanguage", false);
        int count = 0;
        for (ClassEntry ce : model.classes.values()) {
            String fqn = ce.node.name.replace('/', '.');
            if (Wildcard.any(ce.node.name, config.list("antiDecompile.skipClasses")) || Wildcard.any(fqn, config.list("antiDecompile.skipClasses"))) {
                continue;
            }
            if (config.bool("antiDecompile.sourceNoise", true)) {
                if (fakeC) {
                    ce.node.sourceFile = config.string("antiDecompile.cSourceFile", config.string("fakeC.sourceFile", "native_layer.c"));
                    ce.node.sourceDebug = "SMAP\n" + ce.node.sourceFile + "\nC\n*S C\n*F\n+ 1 " + ce.node.sourceFile + "\n" + ce.node.sourceFile + "\n*L\n1#1,4096:1\n*E";
                } else {
                    ce.node.sourceFile = config.string("antiDecompile.sourceFile", "/* synthetic source: while(true){} */.java");
                    ce.node.sourceDebug = "SMAP\nMcShield\nJava\n*S Java\n*F\n+ 1 McShield.java\nMcShield.java\n*L\n1#1,999:1\n*E";
                }
                count++;
            }
            for (MethodNode mn : ce.node.methods) {
                if (config.bool("antiDecompile.stripLocalVariables", false)) {
                    if (mn.localVariables != null) mn.localVariables.clear();
                    if (mn.visibleLocalVariableAnnotations != null) mn.visibleLocalVariableAnnotations.clear();
                    if (mn.invisibleLocalVariableAnnotations != null) mn.invisibleLocalVariableAnnotations.clear();
                }
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
                if (!config.bool("antiDecompile.stripLocalVariables", false) && config.bool("antiDecompile.localVariableNoise", true)) {
                    LabelNode start = new LabelNode();
                    LabelNode end = new LabelNode();
                    mn.instructions.insert(start);
                    mn.instructions.add(end);
                    if (mn.localVariables == null) mn.localVariables = new ArrayList<>();
                    if (fakeC) {
                        mn.localVariables.add(new LocalVariableNode("JNIEnv *env", "Ljava/lang/Object;", null, start, end, 0));
                        mn.localVariables.add(new LocalVariableNode("jobject self", "Ljava/lang/Object;", null, start, end, 0));
                        mn.localVariables.add(new LocalVariableNode("char **argv", "[Ljava/lang/String;", null, start, end, 0));
                        mn.localVariables.add(new LocalVariableNode("uint32_t flags", "I", null, start, end, 0));
                    } else {
                        mn.localVariables.add(new LocalVariableNode("☠ this is not java", "I", null, start, end, 0));
                        mn.localVariables.add(new LocalVariableNode("class", "Ljava/lang/Object;", null, start, end, 0));
                    }
                    if (config.bool("antiDecompile.lineNoise", true)) {
                        mn.instructions.insert(start, new LineNumberNode(fakeC ? 0xC0DE : 65535, start));
                    }
                    count++;
                }
                if (config.bool("antiDecompile.exceptionNoise", true) && !mn.name.equals("<init>") && !mn.name.equals("<clinit>")) {
                    addRethrowTrap(mn);
                    count++;
                }
            }
        }
        return count;
    }

    private void addRethrowTrap(MethodNode mn) {
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        mn.instructions.insert(start);
        mn.instructions.add(end);
        mn.instructions.add(handler);
        mn.instructions.add(new InsnNode(ATHROW));
        if (mn.tryCatchBlocks == null) mn.tryCatchBlocks = new ArrayList<>();
        mn.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/Throwable"));
    }
}
