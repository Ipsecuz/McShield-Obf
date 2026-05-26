package dev.mcshield.obf.io;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.commons.ClassRemapper;
import jdk.internal.org.objectweb.asm.commons.SimpleRemapper;
import jdk.internal.org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JarIO {
    private JarIO() {}

    public static JarModel read(Path input) throws IOException {
        JarModel model = new JarModel();
        try (JarInputStream jis = new JarInputStream(Files.newInputStream(input))) {
            JarEntry entry;
            while ((entry = jis.getNextJarEntry()) != null) {
                if (entry.isDirectory()) continue;
                byte[] bytes = jis.readAllBytes();
                String name = entry.getName();
                if (name.endsWith(".class")) {
                    try {
                        ClassReader cr = new ClassReader(bytes);
                        ClassNode node = new ClassNode(Opcodes.ASM9);
                        cr.accept(node, ClassReader.EXPAND_FRAMES);
                        model.classes.put(node.name, new ClassEntry(name, bytes, node));
                    } catch (Throwable t) {
                        model.resources.put(name, bytes);
                        System.err.println("[mcshield] cannot parse class, copying raw: " + name + " -> " + t.getClass().getSimpleName());
                    }
                } else {
                    model.resources.put(name, bytes);
                }
            }
        }
        byte[] plugin = model.resources.get("plugin.yml");
        if (plugin == null) plugin = model.resources.get("paper-plugin.yml");
        if (plugin != null) model.pluginMainFqn = readYamlScalar(plugin, "main");
        return model;
    }

    public static void write(Path output,
                             JarModel model,
                             ObfConfig config,
                             Map<String, String> remap,
                             Map<String, String> yamlRemap,
                             Map<String, byte[]> generatedClasses,
                             Map<String, byte[]> generatedResources) throws IOException {
        Files.createDirectories(output.toAbsolutePath().getParent() == null ? Path.of(".") : output.toAbsolutePath().getParent());
        Set<String> written = new HashSet<>();
        SimpleRemapper simpleRemapper = new SimpleRemapper(remap);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(output))) {
            for (Map.Entry<String, byte[]> res : model.resources.entrySet()) {
                String name = res.getKey();
                if (shouldDropSignature(name, config)) continue;
                byte[] data = res.getValue();
                if (name.equals("plugin.yml") || name.equals("paper-plugin.yml")) {
                    data = updatePluginYaml(data, yamlRemap == null ? remap : yamlRemap, config);
                } else if (name.equalsIgnoreCase("META-INF/MANIFEST.MF")) {
                    data = updateManifest(data, remap);
                }
                writeEntry(jos, written, name, data);
            }
            for (ClassEntry ce : model.classes.values()) {
                byte[] data = writeRemappedClass(ce, simpleRemapper, config);
                String newName = remap.getOrDefault(ce.node.name, ce.node.name);
                writeEntry(jos, written, newName + ".class", data);
            }
            for (Map.Entry<String, byte[]> gen : generatedClasses.entrySet()) {
                writeEntry(jos, written, gen.getKey() + ".class", remapGeneratedClass(gen.getValue(), simpleRemapper));
            }
            for (Map.Entry<String, byte[]> gen : generatedResources.entrySet()) {
                writeEntry(jos, written, gen.getKey(), gen.getValue());
            }
        }
    }


    public static byte[] remapClassForWrite(ClassEntry ce, Map<String, String> remap, ObfConfig config) {
        return writeRemappedClass(ce, new SimpleRemapper(remap), config);
    }

    private static byte[] remapGeneratedClass(byte[] source, SimpleRemapper remapper) {
        try {
            ClassReader cr = new ClassReader(source);
            SafeClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            cr.accept(new ClassRemapper(cw, remapper), ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Throwable first) {
            try {
                ClassReader cr = new ClassReader(source);
                SafeClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_MAXS);
                cr.accept(new ClassRemapper(cw, remapper), 0);
                return cw.toByteArray();
            } catch (Throwable ignored) {
                return source;
            }
        }
    }

    public static byte[] remapClassBytes(byte[] source, String fromInternal, String toInternal) {
        Map<String, String> map = Map.of(fromInternal, toInternal);
        ClassReader cr = new ClassReader(source);
        // Preserve existing StackMapTable for runtime helpers. Recomputing frames with a partial classpath
        // can make multi-catch handlers too generic and fail verification.
        ClassWriter cw = new ClassWriter(0);
        ClassVisitor cv = new ClassRemapper(cw, new SimpleRemapper(map));
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    public static byte[] remapClassBytes(byte[] source, Map<String, String> map) {
        ClassReader cr = new ClassReader(source);
        ClassWriter cw = new ClassWriter(0);
        ClassVisitor cv = new ClassRemapper(cw, new SimpleRemapper(map));
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    public static byte[] classResource(String internalName) throws IOException {
        String res = "/" + internalName + ".class";
        try (InputStream in = JarIO.class.getResourceAsStream(res)) {
            if (in == null) throw new IOException("Missing runtime class resource " + res);
            return in.readAllBytes();
        }
    }

    private static byte[] writeRemappedClass(ClassEntry ce, SimpleRemapper remapper, ObfConfig config) {
        String frameMode = config.string("frames.mode", config.string("bytecode.frameMode", "compute")).toLowerCase(java.util.Locale.ROOT);

        // VERIFY-SAFE MODE:
        // For some plugins with generic/interface-heavy bytecode, recomputing frames with a partial
        // classpath can collapse interface joins to java/lang/Object. The JVM then rejects later
        // invokeinterface instructions with Bad type on operand stack. In preserve mode, remap
        // directly from the original class bytes and keep the original StackMapTable/max stack.
        // ClassRemapper still updates class names/descriptors/signatures/frames, but no verifier
        // analysis is re-run. Use this mode only with configs that do not mutate real method bodies.
        if (frameMode.equals("preserve") || frameMode.equals("copy") || frameMode.equals("none")) {
            try {
                if (ce.transformed) {
                    // ShellDelegate and other structural transforms add methods/fields but keep original frames.
                    // Recompute max stack/max locals only; do NOT recompute frames for KoraPayments-style
                    // generic/interface bytecode. Without COMPUTE_MAXS, newly generated synthetic methods can
                    // be emitted with max_locals=0 and the JVM throws ClassFormatError: Arguments can't fit into locals.
                    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                    ce.node.accept(new ClassRemapper(cw, remapper));
                    return cw.toByteArray();
                }
                ClassReader cr = new ClassReader(ce.originalBytes);
                ClassWriter cw = new ClassWriter(0);
                ClassVisitor cv = new ClassRemapper(cw, remapper) {
                    @Override
                    public void visitSource(String source, String debug) {
                        if (config.bool("antiDecompile.sourceNoise", false) && ce.node.sourceFile != null) {
                            super.visitSource(ce.node.sourceFile, ce.node.sourceDebug);
                        } else {
                            super.visitSource(source, debug);
                        }
                    }
                };
                cr.accept(cv, 0);
                return cw.toByteArray();
            } catch (Throwable preserveFailed) {
                System.err.println("[mcshield] preserve-frame remap failed for " + ce.node.name + "; falling back to compute-maxs. " + preserveFailed);
                try {
                    ClassReader cr = new ClassReader(ce.originalBytes);
                    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                    cr.accept(new ClassRemapper(cw, remapper), 0);
                    return cw.toByteArray();
                } catch (Throwable second) {
                    System.err.println("[mcshield] remap failed for " + ce.node.name + "; copying original bytes. " + second);
                    return ce.originalBytes;
                }
            }
        }

        try {
            SafeClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            ce.node.accept(new ClassRemapper(cw, remapper));
            return cw.toByteArray();
        } catch (Throwable first) {
            try {
                SafeClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_MAXS);
                ce.node.accept(new ClassRemapper(cw, remapper));
                return cw.toByteArray();
            } catch (Throwable second) {
                System.err.println("[mcshield] remap failed for " + ce.node.name + "; copying original bytes. " + second);
                return ce.originalBytes;
            }
        }
    }

    private static void writeEntry(JarOutputStream jos, Set<String> written, String name, byte[] data) throws IOException {
        if (!written.add(name)) return;
        JarEntry e = new JarEntry(name);
        e.setTime(0L);
        jos.putNextEntry(e);
        jos.write(data);
        jos.closeEntry();
    }

    public static String readYamlScalar(byte[] data, String key) {
        String text = new String(data, StandardCharsets.UTF_8);
        Pattern p = Pattern.compile("(?m)^\\s*" + Pattern.quote(key) + "\\s*:\\s*['\"]?([^'\"#\\r\\n]+)['\"]?.*$");
        Matcher m = p.matcher(text);
        if (m.find()) return m.group(1).trim();
        return null;
    }

    private static byte[] updatePluginYaml(byte[] data, Map<String, String> remap, ObfConfig config) {
        String text = new String(data, StandardCharsets.UTF_8);
        for (String key : config.list("minecraft.updateYamlKeys")) {
            text = updateYamlKey(text, key, remap);
        }
        if (config.list("minecraft.updateYamlKeys").isEmpty()) {
            text = updateYamlKey(text, "main", remap);
            text = updateYamlKey(text, "paper-plugin-loader", remap);
            text = updateYamlKey(text, "bootstrapper", remap);
            text = updateYamlKey(text, "loader", remap);
        }
        if (config.bool("minecraft.pluginMetadata.obfuscate", false)) {
            text = obfuscateTopLevelMetadata(text, config);
        }
        if (config.bool("minecraft.virtualCommands.enabled", false) && config.bool("minecraft.virtualCommands.stripFromYaml", false)) {
            text = stripRealCommandsBlock(text, config);
        }
        if (config.bool("minecraft.virtualPermissions.enabled", false) && config.bool("minecraft.virtualPermissions.stripFromYaml", false)) {
            text = stripYamlBlock(text, "permissions", "");
        }
        if (config.bool("minecraft.commandRename.enabled", false)) {
            text = renameCommandsBlock(text, config);
        } else if (config.bool("minecraft.commandCamouflage.enabled", false)) {
            text = camouflageCommandsBlock(text, config);
        }
        if (config.bool("minecraft.commandDecoys.enabled", false)) {
            text = addCommandDecoys(text, config);
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }




    private static String obfuscateTopLevelMetadata(String text, ObfConfig config) {
        String[] keys = {"author", "authors", "description", "website", "prefix"};
        for (String k : keys) {
            if (config.bool("minecraft.pluginMetadata.keep." + k, false)) continue;
            text = text.replaceAll("(?m)^(" + java.util.regex.Pattern.quote(k) + "\\s*:\\s*).*$", "$1" + noiseText(k, config, k.hashCode()));
        }
        return text;
    }


    private static String stripYamlBlock(String text, String blockName, String replacement) {
        Pattern p = Pattern.compile("(?m)^(\\s*)" + Pattern.quote(blockName) + "\\s*:\\s*(?:#.*)?$");
        Matcher m = p.matcher(text);
        if (!m.find()) return text;
        int indent = m.group(1).length();
        int blockStart = m.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= indent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String repl = replacement == null ? "" : replacement;
        if (!repl.isEmpty() && !repl.endsWith("\n")) repl += "\n";
        return text.substring(0, m.start()) + repl + text.substring(blockEnd);
    }


    private static String stripRealCommandsBlock(String text, ObfConfig config) {
        Pattern p = Pattern.compile("(?m)^(\\s*)commands\\s*:\\s*(?:#.*)?$");
        Matcher m = p.matcher(text);
        if (!m.find()) {
            String eol = text.endsWith("\\n") ? "" : "\\n";
            return text + eol + "commands:\n";
        }
        int cmdIndent = m.group(1).length();
        int blockStart = m.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= cmdIndent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String indent = m.group(1);
        String header = indent + "commands:\n";
        return text.substring(0, m.start()) + header + text.substring(blockEnd);
    }


    private static String camouflageCommandsBlock(String text, ObfConfig config) {
        Pattern p = Pattern.compile("(?m)^(\\s*)commands\\s*:\\s*(?:#.*)?$");
        Matcher m = p.matcher(text);
        if (!m.find()) return text;
        int cmdIndent = m.group(1).length();
        int blockStart = m.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= cmdIndent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String header = text.substring(0, blockStart);
        String block = text.substring(blockStart, blockEnd);
        String tail = text.substring(blockEnd);
        String[] lines = block.split("\n", -1);
        StringBuilder out = new StringBuilder();
        String currentCommand = null;
        int counter = 0;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int ind = 0;
            while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
            Matcher key = Pattern.compile("^(\\s{0," + (cmdIndent + 8) + "})([A-Za-z0-9_-]+)\\s*:\\s*(?:#.*)?$").matcher(line);
            if (ind == cmdIndent + 2 && key.find()) {
                currentCommand = key.group(2).toLowerCase(java.util.Locale.ROOT);
                out.append(line);
                if (i < lines.length - 1) out.append('\n');
                continue;
            }
            String trim = line.trim();
            String prefix = line.substring(0, Math.min(ind, line.length()));
            if (currentCommand != null && config.bool("minecraft.commandCamouflage.obfuscateMetadata", true)) {
                if (trim.startsWith("description:")) {
                    out.append(prefix).append("description: ").append(noiseText(currentCommand, config, counter++));
                    if (i < lines.length - 1) out.append('\n');
                    continue;
                }
                if (trim.startsWith("usage:")) {
                    String usageMode = config.string("minecraft.commandCamouflage.usage", "placeholder");
                    if ("real".equalsIgnoreCase(usageMode)) {
                        out.append(prefix).append("usage: /").append(currentCommand);
                    } else if ("blank".equalsIgnoreCase(usageMode)) {
                        out.append(prefix).append("usage: /<command>");
                    } else {
                        out.append(prefix).append("usage: /<command>");
                    }
                    if (i < lines.length - 1) out.append('\n');
                    continue;
                }
                if (trim.startsWith("permission-message:")) {
                    out.append(prefix).append("permission-message: ").append(noiseText(currentCommand, config, counter++));
                    if (i < lines.length - 1) out.append('\n');
                    continue;
                }
            }
            out.append(line);
            if (i < lines.length - 1) out.append('\n');
        }
        return header + out + tail;
    }

    private static Map<String, String> commandRenameMap(ObfConfig config) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        java.util.List<String> targets = config.list("minecraft.commandRename.targets");
        if (targets.isEmpty()) return out;
        String prefix = config.string("minecraft.commandRename.prefix", "k").toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9_-]", "x");
        if (prefix.isBlank()) prefix = "k";
        long seed = config.seed() == 0 ? 0x6d637368L : config.seed();
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (String raw : targets) {
            if (raw == null || raw.isBlank()) continue;
            String cmd = raw.trim().toLowerCase(java.util.Locale.ROOT);
            long x = (seed ^ cmd.hashCode() * 0x9e3779b97f4a7c15L ^ 0x243f6a8885a308d3L);
            StringBuilder name = new StringBuilder(prefix);
            int len = Math.max(8, config.integer("minecraft.commandRename.nameLength", 18));
            while (name.length() < len) {
                x ^= (x << 13); x ^= (x >>> 7); x ^= (x << 17);
                name.append(alphabet.charAt((int)Math.floorMod(x, alphabet.length())));
            }
            out.put(cmd, name.toString());
        }
        return out;
    }

    private static String renameCommandsBlock(String text, ObfConfig config) {
        Map<String, String> map = commandRenameMap(config);
        if (map.isEmpty()) return text;
        Pattern p = Pattern.compile("(?m)^(\s*)commands\s*:\s*(?:#.*)?$");
        Matcher m = p.matcher(text);
        if (!m.find()) return text;
        int cmdIndent = m.group(1).length();
        int blockStart = m.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= cmdIndent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String header = text.substring(0, blockStart);
        String block = text.substring(blockStart, blockEnd);
        String tail = text.substring(blockEnd);
        String childPrefix = " ".repeat(cmdIndent + 2);
        String grandPrefix = " ".repeat(cmdIndent + 4);
        String[] lines = block.split("\n", -1);
        StringBuilder out = new StringBuilder();
        String currentOriginal = null;
        String currentRenamed = null;
        boolean aliasWrittenForCurrent = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher key = Pattern.compile("^(\s{0," + (cmdIndent + 8) + "})([A-Za-z0-9_-]+)\s*:\s*(?:#.*)?$").matcher(line);
            int ind = 0;
            while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
            if (ind == cmdIndent + 2 && key.find()) {
                if (currentOriginal != null && currentRenamed != null && !aliasWrittenForCurrent) {
                    out.append(grandPrefix).append("aliases: [").append(currentOriginal);
                    appendAliasNoise(out, currentRenamed, config);
                    out.append("]\n");
                }
                currentOriginal = key.group(2).toLowerCase(java.util.Locale.ROOT);
                currentRenamed = map.get(currentOriginal);
                aliasWrittenForCurrent = false;
                if (currentRenamed != null) {
                    out.append(childPrefix).append(currentRenamed).append(":\n");
                    if (config.bool("minecraft.commandRename.obfuscateMetadata", true)) {
                        out.append(grandPrefix).append("description: ").append(noiseText(currentOriginal, config, 0)).append("\n");
                        out.append(grandPrefix).append("usage: /").append(currentRenamed).append("\n");
                    }
                    continue;
                }
            }
            if (currentOriginal != null && currentRenamed != null) {
                String trim = line.trim();
                if (config.bool("minecraft.commandRename.obfuscateMetadata", true) && (trim.startsWith("description:") || trim.startsWith("usage:") || trim.startsWith("permission-message:"))) {
                    continue;
                }
                if (trim.startsWith("aliases:")) {
                    out.append(grandPrefix).append("aliases: [").append(currentOriginal);
                    appendAliasNoise(out, currentRenamed, config);
                    out.append("]\n");
                    aliasWrittenForCurrent = true;
                    continue;
                }
            }
            out.append(line);
            if (i < lines.length - 1) out.append('\n');
        }
        if (currentOriginal != null && currentRenamed != null && !aliasWrittenForCurrent) {
            if (out.length() > 0 && out.charAt(out.length()-1) != '\n') out.append('\n');
            out.append(grandPrefix).append("aliases: [").append(currentOriginal);
            appendAliasNoise(out, currentRenamed, config);
            out.append("]\n");
        }
        return header + out + tail;
    }

    private static void appendAliasNoise(StringBuilder out, String material, ObfConfig config) {
        int n = Math.max(0, config.integer("minecraft.commandRename.aliasNoise", 8));
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        long x = ((config.seed() == 0 ? 0x12345678L : config.seed()) ^ material.hashCode());
        for (int i = 0; i < n; i++) {
            StringBuilder a = new StringBuilder("a");
            while (a.length() < 8) {
                x ^= (x << 13); x ^= (x >>> 7); x ^= (x << 17);
                a.append(alphabet.charAt((int)Math.floorMod(x, alphabet.length())));
            }
            out.append(", ").append(a);
        }
    }

    private static String noiseText(String material, ObfConfig config, int salt) {
        long x = ((config.seed() == 0 ? 0x6d637368L : config.seed()) ^ material.hashCode() ^ salt * 0x9e3779b97f4a7c15L);
        return Integer.toHexString((int)(x >>> 32)) + Integer.toHexString((int)x);
    }

    private static String addCommandDecoys(String text, ObfConfig config) {
        int count = Math.max(0, config.integer("minecraft.commandDecoys.count", 128));
        if (count == 0 || text.contains("# mcshield-command-decoys")) return text;
        if (config.bool("minecraft.commandDecoys.interleave", true)) {
            String mixed = addCommandDecoysInterleaved(text, config, count);
            if (!mixed.equals(text)) return mixed;
        }
        Pattern p = Pattern.compile("(?m)^(\\s*)commands\\s*:\\s*(?:#.*)?$");
        Matcher m = p.matcher(text);
        if (!m.find()) return text;
        String indent = m.group(1);
        String child = indent + "  ";
        StringBuilder block = new StringBuilder();
        block.append(m.group(0)).append(" # mcshield-command-decoys\n");
        for (int i = 0; i < count; i++) block.append(commandDecoyChunk(child, config, text.hashCode(), i));
        return text.substring(0, m.start()) + block + text.substring(m.end() + (m.end() < text.length() && text.charAt(m.end()) == '\n' ? 1 : 0));
    }

    private static String addCommandDecoysInterleaved(String text, ObfConfig config, int count) {
        Pattern p = Pattern.compile("(?m)^(\\s*)commands\\s*:\\s*(?:#.*)?$");
        Matcher m = p.matcher(text);
        if (!m.find()) return text;
        int cmdIndent = m.group(1).length();
        int blockStart = m.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= cmdIndent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String block = text.substring(blockStart, blockEnd);
        String[] lines = block.split("\n", -1);
        java.util.List<String> chunks = new java.util.ArrayList<>();
        StringBuilder prelude = new StringBuilder();
        StringBuilder cur = null;
        Pattern keyPat = Pattern.compile("^(\\s{0," + (cmdIndent + 8) + "})([A-Za-z0-9_-]+)\\s*:\\s*(?:#.*)?$");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int ind = 0;
            while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
            boolean isKey = ind == cmdIndent + 2 && keyPat.matcher(line).find();
            if (isKey) {
                if (cur != null) chunks.add(cur.toString());
                cur = new StringBuilder();
            }
            String withNl = line + (i < lines.length - 1 ? "\n" : "");
            if (cur != null) cur.append(withNl); else prelude.append(withNl);
        }
        if (cur != null) chunks.add(cur.toString());
        if (chunks.isEmpty()) return text;
        String child = " ".repeat(cmdIndent + 2);
        StringBuilder mixed = new StringBuilder();
        mixed.append(text, 0, m.start());
        mixed.append(m.group(0)).append(" # mcshield-command-decoys\n");
        mixed.append(prelude);
        int seed = config.seed() == 0 ? text.hashCode() : (int) config.seed();
        int idx = 0;
        int before = Math.min(count, Math.max(2, count / (chunks.size() + 1)));
        for (int j = 0; j < before; j++) mixed.append(commandDecoyChunk(child, config, seed, idx++));
        for (int c = 0; c < chunks.size(); c++) {
            mixed.append(chunks.get(c));
            int remainingReal = chunks.size() - c - 1;
            int remainingDecoys = count - idx;
            int burst = remainingReal <= 0 ? remainingDecoys : Math.max(1, remainingDecoys / (remainingReal + 1));
            for (int j = 0; j < burst && idx < count; j++) mixed.append(commandDecoyChunk(child, config, seed, idx++));
        }
        mixed.append(text.substring(blockEnd));
        return mixed.toString();
    }

    private static String commandDecoyChunk(String child, ObfConfig config, int seed, int i) {
        String grand = child + "  ";
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        long x = (seed * 1103515245L + i * 0x9e3779b97f4a7c15L) ^ 0x51ed2705L;
        StringBuilder name = new StringBuilder(config.string("minecraft.commandDecoys.prefix", "cmd"));
        int len = 6 + Math.floorMod((int)x, 12);
        for (int j = 0; j < len; j++) {
            x ^= (x << 13); x ^= (x >>> 7); x ^= (x << 17);
            name.append(alphabet.charAt((int)Math.floorMod(x, alphabet.length())));
        }
        String n = name.toString().toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9_-]", "x");
        String[] meta = config.bool("minecraft.commandDecoys.contextualMetadata", true)
                ? new String[] {"Nap tien qua ngan hang", "Nap the cao", "Xem lich su nap", "Quan ly moc nap", "Lenh quan tri", "Xac nhan giao dich", "Huy giao dich", "Kiem tra thanh toan"}
                : new String[] {Integer.toHexString((int)x ^ seed)};
        String desc = meta[Math.floorMod((int)(x ^ i), meta.length)];
        StringBuilder block = new StringBuilder();
        block.append(child).append(n).append(":\n");
        block.append(grand).append("description: ").append(desc).append("\n");
        block.append(grand).append("usage: /<command>\n");
        if (config.bool("minecraft.commandDecoys.aliases", true)) {
            block.append(grand).append("aliases: [").append(n).append("x, ").append(n).append("y]\n");
        }
        return block.toString();
    }

    private static String updateYamlKey(String text, String key, Map<String, String> remap) {
        Pattern p = Pattern.compile("(?m)^(\\s*" + Pattern.quote(key) + "\\s*:\\s*)(['\"]?)([^'\"#\\r\\n]+)(['\"]?)(.*)$");
        Matcher m = p.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String oldFqn = m.group(3).trim();
            String oldInternal = oldFqn.replace('.', '/');
            String mapped = remap.get(oldInternal);
            if (mapped != null) {
                String replacement = m.group(1) + m.group(2) + mapped.replace('/', '.') + m.group(4) + m.group(5);
                m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static byte[] updateManifest(byte[] data, Map<String, String> remap) {
        String text = new String(data, StandardCharsets.UTF_8);
        for (Map.Entry<String, String> e : remap.entrySet()) {
            String oldFqn = e.getKey().replace('/', '.');
            String newFqn = e.getValue().replace('/', '.');
            text = text.replace("Main-Class: " + oldFqn, "Main-Class: " + newFqn);
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static boolean shouldDropSignature(String name, ObfConfig config) {
        if (!config.bool("jar.removeSignatures", true)) return false;
        String upper = name.toUpperCase();
        return upper.startsWith("META-INF/") && (upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC"));
    }

    public static final class SafeClassWriter extends ClassWriter {
        public SafeClassWriter(int flags) { super(flags); }
        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            if (type1.equals(type2)) return type1;
            try {
                ClassLoader loader = ClassLoader.getSystemClassLoader();
                Class<?> c1 = Class.forName(type1.replace('/', '.'), false, loader);
                Class<?> c2 = Class.forName(type2.replace('/', '.'), false, loader);
                if (c1.isAssignableFrom(c2)) return type1;
                if (c2.isAssignableFrom(c1)) return type2;
                if (c1.isInterface() || c2.isInterface()) return "java/lang/Object";
                do {
                    c1 = c1.getSuperclass();
                } while (c1 != null && !c1.isAssignableFrom(c2));
                return c1 == null ? "java/lang/Object" : c1.getName().replace('.', '/');
            } catch (Throwable ignored) {
                if (looksThrowable(type1) && looksThrowable(type2)) return "java/lang/Throwable";
                return "java/lang/Object";
            }
        }
        private boolean looksThrowable(String t) {
            return t.endsWith("Exception") || t.endsWith("Error") || t.equals("java/lang/Throwable");
        }
    }
}
