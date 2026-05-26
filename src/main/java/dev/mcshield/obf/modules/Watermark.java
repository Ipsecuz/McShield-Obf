package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Watermark {
    private final ObfConfig config;

    public Watermark(ObfConfig config) {
        this.config = config;
    }

    public Map<String, byte[]> resources() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.enabled("watermark", false)) return out;
        String buyer = config.string("watermark.buyerId", "unknown");
        String salt = config.string("watermark.salt", "mcshield");
        String hash = sha256(salt + ":" + buyer);
        String path = config.string("watermark.resource", "META-INF/.mcshield/fingerprint.dat");
        String body = "mcshield-watermark-v1\nsha256=" + hash + "\n";
        if (config.bool("watermark.plainInJar", false)) body += "buyer=" + buyer + "\n";
        out.put(path, body.getBytes(StandardCharsets.UTF_8));
        return out;
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode());
        }
    }
}
