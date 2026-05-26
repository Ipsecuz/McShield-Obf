package dev.mcshield.obf.modules;

import java.util.LinkedHashMap;
import java.util.Map;

public final class MappingContext {
    public final Map<String, String> classMap = new LinkedHashMap<>();
    public final Map<String, String> memberMap = new LinkedHashMap<>();

    public Map<String, String> fullMap() {
        Map<String, String> out = new LinkedHashMap<>();
        out.putAll(classMap);
        out.putAll(memberMap);
        return out;
    }
}
