package dev.mcshield.obf.io;

import java.util.LinkedHashMap;
import java.util.Map;

public final class JarModel {
    public final Map<String, ClassEntry> classes = new LinkedHashMap<>();
    public final Map<String, byte[]> resources = new LinkedHashMap<>();
    public String pluginMainFqn;

    public boolean hasClass(String internalName) {
        return classes.containsKey(internalName);
    }
}
