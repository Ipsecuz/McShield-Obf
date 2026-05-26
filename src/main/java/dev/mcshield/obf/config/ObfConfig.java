package dev.mcshield.obf.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Minimal YAML-ish config reader: supports nested maps by 2-space indent, booleans, ints and lists. */
public final class ObfConfig {
    private final Map<String, List<String>> values;

    private ObfConfig(Map<String, List<String>> values) {
        this.values = values;
    }

    public static ObfConfig defaults() {
        return new ObfConfig(new LinkedHashMap<>());
    }

    public static ObfConfig load(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            return defaults();
        }
        Map<String, List<String>> out = new LinkedHashMap<>();
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        String[] stack = new String[32];
        for (String raw : lines) {
            String line = stripComment(raw);
            if (line.trim().isEmpty()) continue;
            int spaces = leadingSpaces(line);
            int level = Math.max(0, spaces / 2);
            String trimmed = line.trim();
            if (trimmed.startsWith("- ")) {
                String val = unquote(trimmed.substring(2).trim());
                String pathKey = join(stack, level);
                if (!pathKey.isEmpty()) add(out, pathKey, val);
                continue;
            }
            int idx = trimmed.indexOf(':');
            if (idx < 0) continue;
            String key = trimmed.substring(0, idx).trim();
            String val = trimmed.substring(idx + 1).trim();
            stack[level] = key;
            for (int i = level + 1; i < stack.length; i++) stack[i] = null;
            String pathKey = join(stack, level + 1);
            if (!val.isEmpty()) {
                if (val.startsWith("[") && val.endsWith("]")) {
                    for (String item : splitInlineList(val.substring(1, val.length() - 1))) {
                        add(out, pathKey, unquote(item.trim()));
                    }
                } else {
                    out.put(pathKey, new ArrayList<>(List.of(unquote(val))));
                }
            }
        }
        return new ObfConfig(out);
    }

    public boolean bool(String key, boolean def) {
        String v = first(key);
        if (v == null) return def;
        v = v.trim().toLowerCase(Locale.ROOT);
        return v.equals("true") || v.equals("yes") || v.equals("on") || v.equals("1");
    }

    public int integer(String key, int def) {
        String v = first(key);
        if (v == null) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException ex) {
            return def;
        }
    }

    public long longValue(String key, long def) {
        String v = first(key);
        if (v == null) return def;
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException ex) {
            return def;
        }
    }

    public String string(String key, String def) {
        String v = first(key);
        return v == null ? def : v;
    }

    public List<String> list(String key) {
        List<String> v = values.get(key);
        return v == null ? Collections.emptyList() : Collections.unmodifiableList(v);
    }

    public long seed() {
        long configured = longValue("seed", 0L);
        if (configured != 0L) return configured;
        return new SecureRandom().nextLong();
    }

    public boolean enabled(String moduleKey, boolean def) {
        return bool(moduleKey + ".enabled", def);
    }

    public void printEffectiveSummary() {
        System.out.println("[mcshield] modules: rename=" + enabled("renaming", true)
                + ", strings=" + enabled("stringEncryption", true) + "/" + string("stringEncryption.mode", "array")
                + ", cflow=" + enabled("controlFlow", true)
                + ", reflection=" + enabled("referenceReflection", true) + "/instance=" + bool("referenceReflection.instance", true)
                + ", fields=" + enabled("fieldReflection", false)
                + ", antiDebug=" + enabled("antiDebug", false)
                + ", antiDecompile=" + enabled("antiDecompile", true)
                + ", fakeC=" + (enabled("fakeC", false) || bool("antiDecompile.fakeCLanguage", false))
                + ", entryProxy=" + enabled("entrypointProxy", false)
                + ", shadowBoot=" + enabled("shadowBoot", false)
                + ", shadowVault=" + enabled("shadowVault", false)
                + ", decoyTree=" + enabled("decoyTree", false)
                + ", deadCode=" + enabled("deadCode", true)
                + ", watermark=" + enabled("watermark", false));
    }

    private String first(String key) {
        List<String> v = values.get(key);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    private static void add(Map<String, List<String>> out, String key, String val) {
        out.computeIfAbsent(key, k -> new ArrayList<>()).add(val);
    }

    private static int leadingSpaces(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == ' ') i++;
        return i;
    }

    private static String join(String[] stack, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (stack[i] == null || stack[i].isEmpty()) break;
            if (sb.length() > 0) sb.append('.');
            sb.append(stack[i]);
        }
        return sb.toString();
    }

    private static String stripComment(String raw) {
        boolean single = false, dbl = false;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\'' && !dbl) single = !single;
            if (c == '"' && !single) dbl = !dbl;
            if (c == '#' && !single && !dbl) return raw.substring(0, i);
        }
        return raw;
    }

    private static String unquote(String v) {
        v = v.trim();
        if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.substring(1, v.length() - 1);
        }
        return v;
    }

    private static List<String> splitInlineList(String s) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean single = false, dbl = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\'' && !dbl) single = !single;
            if (c == '"' && !single) dbl = !dbl;
            if (c == ',' && !single && !dbl) {
                out.add(cur.toString());
                cur.setLength(0);
            } else cur.append(c);
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }
}
