package dev.mcshield.obf.runtime;

import java.lang.management.ManagementFactory;
import java.util.List;

public final class Guard {
    private Guard() {}

    public static void check(String action) {
        if (!debuggerLikely()) return;
        String a = action == null ? "error" : action.toLowerCase();
        if (a.equals("log")) {
            System.err.println("[plugin] debug runtime detected");
            return;
        }
        if (a.equals("silent")) return;
        throw new IllegalStateException("debug runtime detected");
    }

    private static boolean debuggerLikely() {
        List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments();
        for (String a : args) {
            String s = a.toLowerCase();
            if (s.contains("-agentlib:jdwp") || s.contains("-xdebug") || s.contains("jdwp")) return true;
        }
        return false;
    }
}
