package dev.mcshield.obf;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Tiny launcher. The actual bytecode engine uses JDK-internal ASM to keep the final jar self-contained.
 * The launcher re-executes itself once with the required module exports, so users can still run:
 *   java -jar mcshield-obf.jar input.jar output.jar -config obf.yml
 */
public final class McShieldObf {
    private static final String PROP = "mcshield.exported";

    private McShieldObf() {}

    public static void main(String[] args) throws Exception {
        if (!Boolean.getBoolean(PROP) && runningFromJar()) {
            int code = relaunch(args);
            if (code != 0) {
                System.exit(code);
            }
            return;
        }
        Core.run(args);
    }

    private static boolean runningFromJar() {
        try {
            Path p = Path.of(McShieldObf.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return p.toString().endsWith(".jar");
        } catch (URISyntaxException | IllegalArgumentException ex) {
            return false;
        }
    }

    private static int relaunch(String[] args) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", isWindows() ? "java.exe" : "java").toString();
        String jar = Path.of(McShieldObf.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();

        List<String> cmd = new ArrayList<>();
        cmd.add(java);
        cmd.add("-D" + PROP + "=true");
        addExport(cmd, "jdk.internal.org.objectweb.asm");
        addExport(cmd, "jdk.internal.org.objectweb.asm.tree");
        addExport(cmd, "jdk.internal.org.objectweb.asm.commons");
        cmd.add("-jar");
        cmd.add(jar);
        cmd.addAll(Arrays.asList(args));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.inheritIO();
        Process p = pb.start();
        return p.waitFor();
    }

    private static void addExport(List<String> cmd, String pkg) {
        cmd.add("--add-exports=java.base/" + pkg + "=ALL-UNNAMED");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }
}
