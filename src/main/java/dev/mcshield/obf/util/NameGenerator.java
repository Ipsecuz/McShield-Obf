package dev.mcshield.obf.util;

import java.util.HashSet;
import java.util.Locale;
import java.util.Random;
import java.util.Set;

public final class NameGenerator {
    private static final String[] ASCII = "a b c d e f g h i j k l m n o p q r s t u v w x y z".split(" ");
    private static final String[] UNICODE = "α β γ δ ε ζ η θ ι κ λ μ ξ π ρ σ τ φ χ ψ ω Ж Й Ф Ц Ш Ѭ Ӝ".split(" ");
    private static final String[] ICONS = "☃ ♞ ♜ ✦ ✧ ☂ ☯ ⚙ ⚡ ✺ ✹ ❖ ❂ ❉".split(" ");
    private static final String[] MIXED = "a b c α β γ ☃ ♞ ✦ ⚙ x y z λ ψ".split(" ");
    private static final String[] CISH = "sub loc ptr arg env ctx mem reg native jni thunk proc xref node edge call ret".split(" ");
    private static final String[] IL = "I l II ll Il lI III lll IIl IlI lII llI".split(" ");
    private static final String[] ZERO_WIDTH = new String[] {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f"};
    private static final String[] SPOOF = (
            "avxqnel yorvexium zylkorrra nummorath qexvalon iridyxor ulvranek " +
            "vornyxel xeqritan azmuroth kryphalon zeqnaril ovexrune qovlaris " +
            "threnyxal velqorin uxtramon klyvraxis noqzareth yxmarion qirvalen " +
            "driftquartz voidlathe ciphersilt shardmire byteorchid nullcanopy " +
            "morphdeck fluxcairn veilmatrix sigilbranch gloomrelay hazevector " +
            "hexlattice orbitcinder prismthread vaultember wardenmoss glyphdelta " +
            "tensorhollow stackpetal framecobalt methodreef classnimbus " +
            "packetthicket opcodegrove mirrorbasalt switchlichen").split(" ");

    private final String[] alphabet;
    private final Set<String> used = new HashSet<>();
    private final int minLength;
    private final int maxLength;
    private final Random random;
    private long index;

    public NameGenerator(String style) {
        this(style, 0, 0, null);
    }

    public NameGenerator(String style, int minLength, int maxLength, Random random) {
        String s = style == null ? "ascii" : style.toLowerCase(Locale.ROOT);
        if (s.contains("zero") || s.contains("invis")) alphabet = ZERO_WIDTH;
        else if (s.contains("spoof") || s.contains("troll") || s.contains("wall")) alphabet = SPOOF;
        else if (s.equals("il") || s.contains("confuse") || s.contains("homoglyph")) alphabet = IL;
        else if (s.contains("icon")) alphabet = ICONS;
        else if (s.contains("unicode")) alphabet = UNICODE;
        else if (s.contains("mix")) alphabet = MIXED;
        else if (s.equals("c") || s.equals("cish") || s.equals("c-ish") || s.contains("native")) alphabet = CISH;
        else alphabet = ASCII;
        this.minLength = Math.max(0, minLength);
        int hardMax = maxLength <= 0 ? Math.max(0, this.minLength + 32) : maxLength;
        this.maxLength = Math.max(this.minLength, hardMax);
        this.random = random == null ? new Random(0xBADC0FFEE0DDF00DL) : random;
    }

    public String next() {
        while (true) {
            String n = lengthen(encode(index++));
            if (used.add(n)) return n;
        }
    }

    public String nextInternalClass(String basePackage) {
        return nextInternalClass(basePackage, 0, 0, null);
    }

    public String nextInternalClass(String basePackage, int minDepth, int maxDepth, Random random) {
        String p = cleanPackage(basePackage);
        int depth = 0;
        if (maxDepth > 0) {
            int min = Math.max(0, Math.min(minDepth, maxDepth));
            int span = Math.max(0, maxDepth - min);
            depth = min + (random == null || span == 0 ? 0 : random.nextInt(span + 1));
        }
        StringBuilder sb = new StringBuilder(p);
        for (int i = 0; i < depth; i++) {
            if (sb.length() > 0) sb.append('/');
            sb.append(next());
        }
        if (sb.length() > 0) sb.append('/');
        sb.append(next());
        return sb.toString();
    }

    public static String cleanPackage(String basePackage) {
        String p = basePackage == null ? "" : basePackage.trim().replace('.', '/');
        while (p.startsWith("/")) p = p.substring(1);
        while (p.endsWith("/")) p = p.substring(0, p.length() - 1);
        return p;
    }

    private String encode(long value) {
        int base = alphabet.length;
        StringBuilder sb = new StringBuilder();
        long n = value;
        do {
            sb.insert(0, alphabet[(int) (n % base)]);
            n = (n / base) - 1;
        } while (n >= 0);
        return sb.toString();
    }

    private String lengthen(String in) {
        if (minLength <= 0 || in.length() >= minLength) return in;
        StringBuilder sb = new StringBuilder(in);
        int guard = 0;
        int target = maxLength > minLength ? minLength + random.nextInt(Math.max(1, maxLength - minLength + 1)) : minLength;
        while (sb.length() < target && guard++ < 4096) {
            sb.append(alphabet[random.nextInt(alphabet.length)]);
        }
        // Do not hard-truncate: duplicate class names are worse than long names.
        return sb.toString();
    }
}
