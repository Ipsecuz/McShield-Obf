package dev.mcshield.obf.util;

import java.util.List;
import java.util.regex.Pattern;

public final class Wildcard {
    private Wildcard() {}

    public static boolean any(String value, List<String> patterns) {
        if (value == null) return false;
        for (String p : patterns) {
            if (p == null || p.isBlank()) continue;
            if (matches(value, p.trim())) return true;
        }
        return false;
    }

    public static boolean matches(String value, String pattern) {
        if (pattern.equals(value)) return true;
        if (pattern.endsWith(".")) return value.startsWith(pattern);
        if (pattern.endsWith("/")) return value.startsWith(pattern);
        String normalizedPattern = pattern.replace('.', '/');
        String normalizedValue = value.replace('.', '/');
        if (normalizedPattern.equals(normalizedValue)) return true;
        StringBuilder rx = new StringBuilder();
        for (int i = 0; i < normalizedPattern.length(); i++) {
            char c = normalizedPattern.charAt(i);
            if (c == '*') rx.append(".*");
            else if ("\\.[]{}()+-^$?|".indexOf(c) >= 0) rx.append('\\').append(c);
            else rx.append(c);
        }
        return Pattern.matches(rx.toString(), normalizedValue);
    }

    public static String toInternal(String name) {
        return name == null ? null : name.replace('.', '/');
    }

    public static String toFqn(String internal) {
        return internal == null ? null : internal.replace('/', '.');
    }
}
