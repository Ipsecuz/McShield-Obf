package boot;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Small optional native probe used by McShield-generated shells. */
public final class Axis {
    private static volatile boolean ok;
    static {
        try {
            loadNative();
            ok = (probe(0x5A17C0DE) == 0x3774B3F4);
        } catch (Throwable ignored) {
            ok = false;
        }
    }
    private Axis() {}
    public static void touch() {
        if (!ok && Boolean.getBoolean("mcshield.native.required")) {
            throw new IllegalStateException("native guard unavailable");
        }
    }
    private static native int probe(int x);
    private static void loadNative() throws Exception {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        String res = null;
        if (os.contains("linux") && (arch.contains("64") || arch.contains("amd64") || arch.contains("x86_64"))) {
            res = "/META-INF/.mcshield/native/linux-x86_64/libmcsng.so";
        }
        if (res == null) return;
        try (InputStream in = Axis.class.getResourceAsStream(res)) {
            if (in == null) return;
            Path p = Files.createTempFile("mcsng-", ".so");
            Files.copy(in, p, StandardCopyOption.REPLACE_EXISTING);
            System.load(p.toAbsolutePath().toString());
            p.toFile().deleteOnExit();
        }
    }
}
