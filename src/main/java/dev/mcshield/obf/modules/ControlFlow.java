package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.Bytecode;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.MethodNode;

import java.util.Random;

public final class ControlFlow implements Opcodes {
    private final ObfConfig config;
    private final Random random;

    public ControlFlow(ObfConfig config, long seed) {
        this.config = config;
        this.random = new Random(seed ^ 0xC0FFEE);
    }

    public int apply(JarModel model) {
        if (!config.enabled("controlFlow", true)) return 0;
        int level = Math.max(1, config.integer("controlFlow.level", 1));
        int count = 0;
        for (ClassEntry ce : model.classes.values()) {
            if (Wildcard.any(ce.node.name, config.list("controlFlow.skipClasses"))) continue;
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
                for (int i = 0; i < level; i++) {
                    mn.instructions.insert(Bytecode.opaqueThrowBlock(random.nextInt()));
                    count++;
                }
            }
        }
        return count;
    }
}
