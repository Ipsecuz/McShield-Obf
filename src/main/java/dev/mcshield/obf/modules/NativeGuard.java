package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.JarIO;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.*;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

/** Optional real native C probe. It is non-fatal by default so hosted servers do not break. */
public final class NativeGuard implements Opcodes {
    public static final String AXIS_OWNER = "boot/Axis";
    private final ObfConfig config;

    public NativeGuard(ObfConfig config) { this.config = config; }

    public int apply(Map<String, byte[]> generatedClasses, Map<String, byte[]> generatedResources, String shellOwner) {
        if (!config.enabled("nativeGuard", false)) return 0;
        try {
            byte[] cls = JarIO.classResource(AXIS_OWNER);
            generatedClasses.put(AXIS_OWNER, cls);
            byte[] so = resource("/META-INF/mcshield-native/linux-x86_64/libmcsng.so");
            if (so != null) generatedResources.put("META-INF/.mcshield/native/linux-x86_64/libmcsng.so", so);
            if (shellOwner != null && generatedClasses.containsKey(shellOwner)) {
                generatedClasses.put(shellOwner, inject(generatedClasses.get(shellOwner)));
                return 2;
            }
            return 1;
        } catch (Throwable t) {
            System.err.println("[mcshield] nativeGuard skipped: " + t);
            return 0;
        }
    }

    private byte[] resource(String path) throws Exception {
        try (InputStream in = NativeGuard.class.getResourceAsStream(path)) {
            return in == null ? null : in.readAllBytes();
        }
    }

    private byte[] inject(byte[] shellBytes) throws Exception {
        ClassNode cn = new ClassNode(ASM9);
        new ClassReader(shellBytes).accept(cn, 0);
        for (MethodNode mn : cn.methods) {
            if ((mn.name.equals("onLoad") || mn.name.equals("onEnable")) && mn.desc.equals("()V")) {
                InsnList il = new InsnList();
                il.add(new MethodInsnNode(INVOKESTATIC, AXIS_OWNER, "touch", "()V", false));
                mn.instructions.insert(il);
            }
        }
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }
}
