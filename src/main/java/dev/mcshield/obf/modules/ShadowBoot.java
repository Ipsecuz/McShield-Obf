package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ShadowBoot is McShield's clean public entry facade.
 *
 * plugin.yml points at a short, brand-neutral class such as boot.Pivot.
 * That class contains no plugin logic: it only inherits from the already-obfuscated
 * proxy/real main chain. Decompiling the public main gives a constructor and a
 * superclass reference, while the real lifecycle methods remain elsewhere.
 *
 * This intentionally does not copy the naming/resource layout of other protectors.
 */
public final class ShadowBoot implements Opcodes {
    private final ObfConfig config;

    public ShadowBoot(ObfConfig config) {
        this.config = config;
    }

    public Result apply(JarModel model,
                        MappingContext mapping,
                        EntryPointProxy.Result entryProxy,
                        Map<String, byte[]> generatedClasses,
                        Map<String, byte[]> generatedResources) {
        if (!config.enabled("shadowBoot", false)) return Result.disabled();
        if (model.pluginMainFqn == null || model.pluginMainFqn.isBlank()) return Result.disabled();

        String oldMain = model.pluginMainFqn.replace('.', '/');
        ClassEntry mainEntry = model.classes.get(oldMain);
        if (mainEntry == null) {
            System.err.println("[mcshield] shadowBoot skipped: main class not found in input model: " + oldMain);
            return Result.disabled();
        }
        MethodNode init = noArgConstructor(mainEntry.node);
        if (init == null || (init.access & ACC_PRIVATE) != 0) {
            System.err.println("[mcshield] shadowBoot skipped: main class needs non-private no-arg constructor: " + oldMain);
            return Result.disabled();
        }

        // The public boot facade subclasses the proxy leaf when entrypointProxy is enabled.
        // Otherwise it subclasses the real main; ClassRemapper later remaps that superclass.
        mainEntry.node.access &= ~ACC_FINAL;
        String targetSuper = entryProxy != null && entryProxy.enabled() ? entryProxy.proxyOwner() : oldMain;
        String publicOwner = normalizeOwner(config.string("shadowBoot.publicMain", "boot.Pivot"));
        if (publicOwner.isBlank()) publicOwner = "boot/Pivot";
        if (model.classes.containsKey(publicOwner) || generatedClasses.containsKey(publicOwner)) {
            publicOwner = unique(publicOwner, model, generatedClasses);
        }

        generatedClasses.put(publicOwner, generateFacade(publicOwner, targetSuper));
        generatedResources.putAll(resources(publicOwner, targetSuper));

        Map<String, String> yaml = new LinkedHashMap<>(mapping.fullMap());
        yaml.put(oldMain, publicOwner);
        return new Result(true, publicOwner, targetSuper, yaml);
    }

    private MethodNode noArgConstructor(ClassNode cn) {
        for (MethodNode mn : cn.methods) if (mn.name.equals("<init>") && mn.desc.equals("()V")) return mn;
        return null;
    }

    private String unique(String base, JarModel model, Map<String, byte[]> generatedClasses) {
        int i = 1;
        String stem = base;
        while (stem.endsWith("/")) stem = stem.substring(0, stem.length() - 1);
        while (true) {
            String candidate = stem + i;
            if (!model.classes.containsKey(candidate) && !generatedClasses.containsKey(candidate)) return candidate;
            i++;
        }
    }

    private byte[] generateFacade(String owner, String superOwner) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = owner;
        cn.superName = superOwner;
        cn.sourceFile = config.string("shadowBoot.sourceFile", "pivot.c");
        if (config.bool("shadowBoot.fakeDebug", true)) {
            cn.sourceDebug = "SMAP\n" + cn.sourceFile + "\nC\n*S C\n*F\n+ 1 " + cn.sourceFile + "\n" + cn.sourceFile + "\n*L\n1#1,2048:1\n*E";
        }

        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);

        if (config.bool("shadowBoot.lifecycleBridge", true)) addLifecycleBridge(cn, owner, superOwner);

        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }


    private void addLifecycleBridge(ClassNode cn, String owner, String superOwner) {
        MethodNode onLoad = new MethodNode(ACC_PUBLIC, "onLoad", "()V", null, null);
        addNoise(onLoad, owner.hashCode());
        onLoad.instructions.add(new VarInsnNode(ALOAD, 0));
        onLoad.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onLoad", "()V", false));
        onLoad.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onLoad);

        MethodNode onEnable = new MethodNode(ACC_PUBLIC, "onEnable", "()V", null, null);
        addNoise(onEnable, owner.length() ^ superOwner.hashCode());
        onEnable.instructions.add(new VarInsnNode(ALOAD, 0));
        onEnable.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onEnable", "()V", false));
        onEnable.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onEnable);

        MethodNode onDisable = new MethodNode(ACC_PUBLIC, "onDisable", "()V", null, null);
        addNoise(onDisable, owner.hashCode() ^ 0x22);
        onDisable.instructions.add(new VarInsnNode(ALOAD, 0));
        onDisable.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onDisable", "()V", false));
        onDisable.instructions.add(new InsnNode(RETURN));
        cn.methods.add(onDisable);

        MethodNode onCommand = new MethodNode(ACC_PUBLIC, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", null, null);
        addNoise(onCommand, owner.hashCode() ^ 0x33);
        onCommand.instructions.add(new VarInsnNode(ALOAD, 0));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 1));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 2));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 3));
        onCommand.instructions.add(new VarInsnNode(ALOAD, 4));
        onCommand.instructions.add(new MethodInsnNode(INVOKESPECIAL, superOwner, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", false));
        onCommand.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(onCommand);
    }

    private void addNoise(MethodNode m, int v) {
        pushInt(m, v ^ 0x11335577);
        pushInt(m, Integer.rotateLeft(v, 5));
        m.instructions.add(new InsnNode(IXOR));
        m.instructions.add(new InsnNode(POP));
    }

    private void pushInt(MethodNode m, int v) {
        if (v >= -1 && v <= 5) m.instructions.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) m.instructions.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) m.instructions.add(new IntInsnNode(SIPUSH, v));
        else m.instructions.add(new LdcInsnNode(v));
    }

    private Map<String, byte[]> resources(String publicOwner, String targetSuper) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.bool("shadowBoot.emitMetadata", true)) return out;
        String root = normalizeResource(config.string("shadowBoot.metadataRoot", "META-INF/.mcshield/shadow"));
        String text = "format=mcshield-shadow-v1\n"
                + "entry=" + xor(publicOwner.replace('/', '.'), 0x33) + "\n"
                + "route=" + xor(targetSuper.replace('/', '.'), 0x55) + "\n"
                + "note=generated\n";
        out.put(root + "/route.dat", text.getBytes(StandardCharsets.UTF_8));
        out.put(root + "/index/" + Integer.toHexString(publicOwner.hashCode()) + ".idx",
                ("v=1\n" + Integer.toHexString((publicOwner + targetSuper).hashCode()) + "\n").getBytes(StandardCharsets.UTF_8));
        return out;
    }

    private static String xor(String s, int k) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            int v = s.charAt(i) ^ (k + i * 17);
            if (i > 0) sb.append(',');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    private static String normalizeOwner(String s) {
        if (s == null) return "";
        String out = s.trim().replace('.', '/');
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length() - 1);
        return out;
    }

    private static String normalizeResource(String s) {
        if (s == null) return "META-INF/.mcshield/shadow";
        String out = s.trim().replace('\\', '/');
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length() - 1);
        return out.isBlank() ? "META-INF/.mcshield/shadow" : out;
    }

    public record Result(boolean enabled, String publicOwner, String targetSuper, Map<String, String> yamlRemap) {
        static Result disabled() { return new Result(false, null, null, null); }
    }
}
