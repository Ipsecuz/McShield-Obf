package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.LabelNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * Experimental protected runtime mode.
 *
 * The public plugin.yml main is a clean JavaPlugin facade. Real plugin classes are removed from
 * normal .class entries and stored as encrypted .bin resources loaded at runtime. This is a distinct
 * McShield layout and intentionally avoids cloning naming/resource layouts from other protectors.
 */
public final class ShadowVault implements Opcodes {
    public static final String BASE_RUNTIME_OWNER = "dev/mcshield/obf/runtime/ShadowVaultRuntime";
    private static final String INIT_METHOD = "__mcshield$shadow$init";
    private final ObfConfig config;
    private final long seed;

    public ShadowVault(ObfConfig config, long seed) {
        this.config = config;
        this.seed = seed;
    }

    public Result apply(JarModel model,
                        MappingContext mapping,
                        Map<String, byte[]> generatedClasses,
                        Map<String, byte[]> generatedResources) {
        if (!config.enabled("shadowVault", false)) return Result.disabled();
        if (model.pluginMainFqn == null || model.pluginMainFqn.isBlank()) return Result.disabled();
        String oldMain = model.pluginMainFqn.replace('.', '/');
        if (!model.classes.containsKey(oldMain)) {
            System.err.println("[mcshield] shadowVault skipped: main class not found: " + oldMain);
            return Result.disabled();
        }

        if (config.bool("shadowVault.constructorHook", true)) {
            installConstructorHook(model, oldMain);
        }

        String publicOwner = normalizeOwner(config.string("shadowVault.publicMain", "boot.Pivot"));
        if (publicOwner.isBlank()) publicOwner = "boot/Pivot";
        String runtimeDefault = config.bool("shadowVault.hardenRuntime", true) ? ("boot/" + hash("rt" + seed + oldMain).substring(0, 12)) : "boot.Link";
        String runtimeOwner = normalizeOwner(config.string("shadowVault.runtimeOwner", runtimeDefault));
        if (runtimeOwner.isBlank()) runtimeOwner = normalizeOwner(runtimeDefault);
        String root = normalizeResource(config.string("shadowVault.resourceRoot", "META-INF/.mcshield/vault"));
        String index = root + "/" + hash("idx" + seed + oldMain) + ".idx";
        int key = config.integer("shadowVault.key", (int)(seed ^ 0x6d637376));
        if (key == 0) key = 0x13579bdf;

        Map<String, byte[]> protectedClasses = new LinkedHashMap<>();
        Map<String, String> classToResource = new LinkedHashMap<>();
        List<String> protect = new ArrayList<>(model.classes.keySet());
        for (String owner : protect) {
            if (owner.equals(publicOwner) || owner.equals(runtimeOwner) || shouldSkip(owner)) continue;
            ClassEntry ce = model.classes.get(owner);
            if (ce == null) continue;
            String mapped = mapping.classMap.getOrDefault(owner, owner);
            byte[] remapped = JarIO.remapClassForWrite(ce, mapping.fullMap(), config);
            String res = root + "/c/" + hash(mapped + seed) + ".bin";
            protectedClasses.put(res, xor(gzip(remapped), key ^ mapped.replace('/', '.').hashCode()));
            classToResource.put(mapped.replace('/', '.'), res);
            model.classes.remove(owner);
        }

        String mappedMain = mapping.classMap.getOrDefault(oldMain, oldMain).replace('/', '.');
        byte[] idx = binaryIndex(classToResource, commandNames(model));

        generatedResources.putAll(protectedClasses);
        generatedResources.put(index, xor(idx, key ^ 0x51f15e));
        generatedClasses.put(publicOwner, generatePivot(publicOwner, runtimeOwner, index, mappedMain, key));
        try {
            String loaderOwner = runtimeOwner + "$" + hash("vl" + seed + oldMain).substring(0, 10);
            String entryOwner = runtimeOwner + "$" + hash("ve" + seed + oldMain).substring(0, 10);
            Map<String, String> rtMap = new LinkedHashMap<>();
            rtMap.put(BASE_RUNTIME_OWNER, runtimeOwner);
            rtMap.put(BASE_RUNTIME_OWNER + "$VaultLoader", loaderOwner);
            rtMap.put(BASE_RUNTIME_OWNER + "$Entry", entryOwner);
            generatedClasses.put(runtimeOwner, polishRuntime(JarIO.remapClassBytes(JarIO.classResource(BASE_RUNTIME_OWNER), rtMap), runtimeOwner));
            generatedClasses.put(loaderOwner, polishRuntime(JarIO.remapClassBytes(JarIO.classResource(BASE_RUNTIME_OWNER + "$VaultLoader"), rtMap), loaderOwner));
            generatedClasses.put(entryOwner, polishRuntime(JarIO.remapClassBytes(JarIO.classResource(BASE_RUNTIME_OWNER + "$Entry"), rtMap), entryOwner));
        } catch (Exception e) {
            throw new IllegalStateException("Missing ShadowVault runtime helper", e);
        }

        if (config.bool("shadowVault.virtualizePluginYaml", false)) virtualizePluginYaml(model, root);

        Map<String, String> yaml = new LinkedHashMap<>(mapping.fullMap());
        yaml.put(oldMain, publicOwner);
        return new Result(true, publicOwner, mappedMain, index, classToResource.size(), yaml);
    }

    private byte[] polishRuntime(byte[] bytes, String owner) {
        try {
            ClassNode cn = new ClassNode(ASM9);
            new ClassReader(bytes).accept(cn, 0);
            cn.sourceFile = config.string("shadowVault.runtimeSourceFile", "module.c");
            cn.sourceDebug = null;
            ClassWriter cw = new ClassWriter(0);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Throwable ignored) {
            return bytes;
        }
    }


    private void installConstructorHook(JarModel model, String oldMain) {
        ClassEntry ce = model.classes.get(oldMain);
        if (ce == null) return;
        try {
            ClassNode cn = new ClassNode(ASM9);
            new ClassReader(ce.originalBytes).accept(cn, 0);
            if (!"org/bukkit/plugin/java/JavaPlugin".equals(cn.superName) && !extendsJavaPlugin(cn, model)) return;
            for (MethodNode m : cn.methods) {
                if (INIT_METHOD.equals(m.name) && "()V".equals(m.desc)) return;
            }
            MethodNode ctor = null;
            for (MethodNode m : cn.methods) {
                if ("<init>".equals(m.name) && "()V".equals(m.desc)) { ctor = m; break; }
            }
            if (ctor == null) return;
            MethodNode hook = cloneConstructorTail(ctor);
            if (hook == null) return;
            cn.methods.add(hook);
            ClassWriter cw = new ClassWriter(0);
            cn.accept(cw);
            model.classes.put(oldMain, new ClassEntry(ce.originalPath, cw.toByteArray(), cn));
        } catch (Throwable ignored) {}
    }

    private boolean extendsJavaPlugin(ClassNode cn, JarModel model) {
        String s = cn.superName;
        int guard = 0;
        while (s != null && guard++ < 32) {
            if ("org/bukkit/plugin/java/JavaPlugin".equals(s)) return true;
            ClassEntry ce = model.classes.get(s);
            if (ce == null) return false;
            try {
                ClassNode scn = new ClassNode(ASM9);
                new ClassReader(ce.originalBytes).accept(scn, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                s = scn.superName;
            } catch (Throwable t) {
                return false;
            }
        }
        return false;
    }

    private MethodNode cloneConstructorTail(MethodNode ctor) {
        AbstractInsnNode start = null;
        for (AbstractInsnNode insn = ctor.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode mi && "<init>".equals(mi.name)) {
                start = insn.getNext();
                break;
            }
        }
        if (start == null) return null;
        MethodNode hook = new MethodNode(ACC_PRIVATE | ACC_SYNTHETIC, INIT_METHOD, "()V", null, null);
        HashMap<LabelNode, LabelNode> labels = new HashMap<>();
        for (AbstractInsnNode insn = start; insn != null; insn = insn.getNext()) {
            if (insn.getType() == AbstractInsnNode.FRAME || insn.getType() == AbstractInsnNode.LINE) continue;
            hook.instructions.add(insn.clone(labels));
        }
        hook.maxLocals = Math.max(1, ctor.maxLocals);
        hook.maxStack = Math.max(1, ctor.maxStack);
        return hook;
    }

    private boolean shouldSkip(String owner) {
        String dotted = owner.replace('/', '.');
        for (String p : config.list("shadowVault.skipPackages")) {
            if (!p.isBlank() && dotted.startsWith(p)) return true;
        }
        for (String p : config.list("renaming.keepPackages")) {
            if (!p.isBlank() && dotted.startsWith(p)) return true;
        }
        return false;
    }

    private byte[] generatePivot(String owner, String runtimeOwner, String indexResource, String mainClass, int key) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = owner;
        cn.superName = "org/bukkit/plugin/java/JavaPlugin";
        cn.sourceFile = config.string("shadowVault.sourceFile", "pivot.c");

        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "org/bukkit/plugin/java/JavaPlugin", "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        cn.methods.add(init);

        cn.methods.add(lifecycle("onLoad", runtimeOwner, "onLoad", indexResource, mainClass, key));
        cn.methods.add(lifecycle("onEnable", runtimeOwner, "onEnable", indexResource, mainClass, key));
        cn.methods.add(lifecycle("onDisable", runtimeOwner, "onDisable", indexResource, mainClass, key));
        if (config.bool("shadowVault.commandBridge", true)) {
            cn.methods.add(commandBridge(runtimeOwner, indexResource, mainClass, key));
            cn.methods.add(tabBridge(runtimeOwner, indexResource, mainClass, key));
        }

        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private MethodNode lifecycle(String name, String runtimeOwner, String runtimeMethod, String index, String main, int key) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, name, "()V", null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        emitIntArray(mn, encodeInts(index, key ^ 0x2468ace));
        emitIntArray(mn, encodeInts(main, key ^ 0x13579bdf));
        mn.instructions.add(new LdcInsnNode(key));
        mn.instructions.add(new MethodInsnNode(INVOKESTATIC, runtimeOwner, runtimeMethod, "(Ljava/lang/Object;[I[II)V", false));
        mn.instructions.add(new InsnNode(RETURN));
        return mn;
    }

    private MethodNode commandBridge(String runtimeOwner, String index, String main, int key) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new VarInsnNode(ALOAD, 3));
        mn.instructions.add(new VarInsnNode(ALOAD, 4));
        emitIntArray(mn, encodeInts(index, key ^ 0x2468ace));
        emitIntArray(mn, encodeInts(main, key ^ 0x13579bdf));
        mn.instructions.add(new LdcInsnNode(key));
        mn.instructions.add(new MethodInsnNode(INVOKESTATIC, runtimeOwner, "onCommand", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/String;[I[II)Z", false));
        mn.instructions.add(new InsnNode(IRETURN));
        return mn;
    }

    private MethodNode tabBridge(String runtimeOwner, String index, String main, int key) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, "onTabComplete", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;", null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new VarInsnNode(ALOAD, 3));
        mn.instructions.add(new VarInsnNode(ALOAD, 4));
        emitIntArray(mn, encodeInts(index, key ^ 0x2468ace));
        emitIntArray(mn, encodeInts(main, key ^ 0x13579bdf));
        mn.instructions.add(new LdcInsnNode(key));
        mn.instructions.add(new MethodInsnNode(INVOKESTATIC, runtimeOwner, "onTabComplete", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/String;[I[II)Ljava/util/List;", false));
        mn.instructions.add(new InsnNode(ARETURN));
        return mn;
    }

    private void emitIntArray(MethodNode mn, int[] data) {
        mn.instructions.add(new LdcInsnNode(data.length));
        mn.instructions.add(new IntInsnNode(NEWARRAY, T_INT));
        for (int i = 0; i < data.length; i++) {
            mn.instructions.add(new InsnNode(DUP));
            mn.instructions.add(new LdcInsnNode(i));
            mn.instructions.add(new LdcInsnNode(data[i]));
            mn.instructions.add(new InsnNode(IASTORE));
        }
    }

    private int[] encodeInts(String s, int key) {
        int[] out = new int[s.length()];
        int x = key ^ 0x5a17c0de;
        for (int i = 0; i < s.length(); i++) {
            x = x * 1664525 + 1013904223;
            out[i] = s.charAt(i) ^ (x >>> 16) ^ (i * 131);
        }
        return out;
    }

    private static byte[] binaryIndex(Map<String, String> classToResource, List<String> commands) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            dos.writeInt(0x4d535631);
            dos.writeInt(classToResource.size());
            for (Map.Entry<String, String> e : classToResource.entrySet()) {
                dos.writeUTF(e.getKey());
                dos.writeUTF(e.getValue());
            }
            dos.writeInt(commands.size());
            for (String c : commands) dos.writeUTF(c);
            dos.flush();
            return bos.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private List<String> commandNames(JarModel model) {
        List<String> out = new ArrayList<>();
        byte[] yml = model.resources.get("plugin.yml");
        if (yml == null) yml = model.resources.get("paper-plugin.yml");
        if (yml == null) return out;
        String text = new String(yml, StandardCharsets.UTF_8);
        boolean in = false;
        int baseIndent = -1;
        for (String raw : text.split("\n")) {
            String line = raw.replace("\r", "");
            if (line.trim().isEmpty() || line.trim().startsWith("#")) continue;
            int indent = leading(line);
            String t = line.trim();
            if (t.matches("commands\\s*:.*")) { in = true; baseIndent = indent; continue; }
            if (in && indent <= baseIndent && !t.startsWith("-")) break;
            if (in && indent == baseIndent + 2 && t.endsWith(":")) {
                String n = t.substring(0, t.length() - 1).trim();
                if (!n.isEmpty() && !n.contains(" ")) out.add(n);
            }
        }
        return out;
    }

    private void virtualizePluginYaml(JarModel model, String root) {
        byte[] yml = model.resources.get("plugin.yml");
        String name = "plugin.yml";
        if (yml == null) { yml = model.resources.get("paper-plugin.yml"); name = "paper-plugin.yml"; }
        if (yml == null) return;
        model.resources.put(root + "/descriptor.yml", yml);
        String text = new String(yml, StandardCharsets.UTF_8);
        text = stripTopLevelBlock(text, "commands");
        text = stripTopLevelBlock(text, "permissions");
        model.resources.put(name, text.getBytes(StandardCharsets.UTF_8));
    }

    private static String stripTopLevelBlock(String text, String key) {
        StringBuilder out = new StringBuilder();
        boolean skip = false;
        int base = -1;
        for (String raw : text.split("(?<=\\n)", -1)) {
            String noNl = raw.endsWith("\n") ? raw.substring(0, raw.length()-1) : raw;
            String trimmed = noNl.trim();
            int indent = leading(noNl);
            if (!skip && trimmed.matches(java.util.regex.Pattern.quote(key) + "\\s*:.*")) { skip = true; base = indent; continue; }
            if (skip) {
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                if (indent > base) continue;
                skip = false;
            }
            if (!skip) out.append(raw);
        }
        return out.toString();
    }

    private static int leading(String s) { int i=0; while (i<s.length() && s.charAt(i)==' ') i++; return i; }

    private static byte[] gzip(byte[] in) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (GZIPOutputStream gos = new GZIPOutputStream(bos)) { gos.write(in); }
            return bos.toByteArray();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static byte[] xor(byte[] in, int key) {
        byte[] out = new byte[in.length];
        int s = key;
        for (int i = 0; i < in.length; i++) {
            s = s * 1103515245 + 12345;
            out[i] = (byte)(in[i] ^ (s >>> 16));
        }
        return out;
    }

    private static String hash(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] b = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i=0; i<10; i++) sb.append(String.format(Locale.ROOT, "%02x", b[i]));
            return sb.toString();
        } catch (Exception e) { return Integer.toHexString(s.hashCode()); }
    }

    private static String normalizeOwner(String s) {
        if (s == null) return "";
        String out = s.trim().replace('.', '/');
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length()-1);
        return out;
    }
    private static String normalizeResource(String s) {
        if (s == null) return "META-INF/.mcshield/vault";
        String out = s.trim().replace('\\', '/');
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length()-1);
        return out.isBlank() ? "META-INF/.mcshield/vault" : out;
    }

    public record Result(boolean enabled, String publicOwner, String mainClass, String indexResource, int protectedClasses, Map<String,String> yamlRemap) {
        static Result disabled() { return new Result(false, null, null, null, 0, null); }
    }
}
