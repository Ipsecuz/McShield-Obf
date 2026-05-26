package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.LineNumberNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;

public final class Optimizer {
    private final ObfConfig config;

    public Optimizer(ObfConfig config) {
        this.config = config;
    }

    public int apply(JarModel model) {
        if (!config.enabled("optimizer", false)) return 0;
        int changed = 0;
        for (ClassEntry ce : model.classes.values()) {
            if (config.bool("optimizer.removeDebug", false)) {
                ce.node.sourceDebug = null;
                ce.node.sourceFile = null;
                for (MethodNode mn : ce.node.methods) {
                    mn.localVariables = null;
                    if (mn.instructions != null) {
                        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
                            AbstractInsnNode next = insn.getNext();
                            if (insn instanceof LineNumberNode) mn.instructions.remove(insn);
                            insn = next;
                        }
                    }
                }
                changed++;
            }
        }
        return changed;
    }
}
