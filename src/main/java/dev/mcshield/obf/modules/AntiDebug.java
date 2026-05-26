package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.InsnList;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;

public final class AntiDebug implements Opcodes {
    public static final String BASE_OWNER = "dev/mcshield/obf/runtime/Guard";

    private final ObfConfig config;
    private final String guardOwner;

    public AntiDebug(ObfConfig config, String guardOwner) {
        this.config = config;
        this.guardOwner = guardOwner;
    }

    public int apply(JarModel model) {
        if (!config.enabled("antiDebug", false)) return 0;
        String main = model.pluginMainFqn == null ? null : model.pluginMainFqn.replace('.', '/');
        String action = config.string("antiDebug.action", "error");
        int count = 0;
        for (ClassEntry ce : model.classes.values()) {
            boolean mainClass = main != null && main.equals(ce.node.name);
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                boolean inject = mainClass && mn.name.equals("onEnable") && mn.desc.equals("()V");
                if (!inject && config.string("antiDebug.scope", "onEnable").equalsIgnoreCase("allMethods")) {
                    inject = !mn.name.equals("<init>") && !mn.name.equals("<clinit>");
                }
                if (inject) {
                    InsnList il = new InsnList();
                    il.add(new LdcInsnNode(action));
                    il.add(new MethodInsnNode(INVOKESTATIC, guardOwner, "check", "(Ljava/lang/String;)V", false));
                    mn.instructions.insert(il);
                    count++;
                }
            }
        }
        return count;
    }
}
