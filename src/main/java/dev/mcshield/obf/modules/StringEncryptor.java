package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.Bytecode;
import dev.mcshield.obf.util.NameGenerator;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.Handle;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.InsnList;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.InvokeDynamicInsnNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;

import java.util.Locale;
import java.util.Random;

public final class StringEncryptor implements Opcodes {
    public static final String BASE_OWNER = "dev/mcshield/obf/runtime/Strings";
    public static final String BSM_STRING_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;I)Ljava/lang/invoke/CallSite;";

    private final ObfConfig config;
    private final Random random;
    private final String helperOwner;
    private final NameGenerator indyNames;

    public StringEncryptor(ObfConfig config, long seed, String helperOwner) {
        this.config = config;
        this.random = new Random(seed ^ 0x51A7BEEFL);
        this.helperOwner = helperOwner;
        this.indyNames = new NameGenerator(config.string("stringEncryption.indyNameStyle", config.string("renaming.memberStyle", "ascii")));
    }

    public int apply(JarModel model) {
        if (!config.enabled("stringEncryption", true)) return 0;
        int minLen = config.integer("stringEncryption.minLength", 2);
        int maxArray = Math.max(16, config.integer("stringEncryption.arrayMaxLength", 4096));
        int methodBudget = Math.max(0, config.integer("stringEncryption.arrayMethodBudget", 12000));
        String overflowMode = config.string("stringEncryption.overflowMode", "indy");
        String mode = config.string("stringEncryption.mode", "array");
        int changed = 0;
        for (ClassEntry ce : model.classes.values()) {
            String fqn = ce.node.name.replace('/', '.');
            if (Wildcard.any(ce.node.name, config.list("stringEncryption.skipClasses")) || Wildcard.any(fqn, config.list("stringEncryption.skipClasses"))) continue;
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null) continue;
                int budgetUsed = 0;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
                    AbstractInsnNode next = insn.getNext();
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                        if (shouldEncrypt(s, minLen)) {
                            int keyA = random.nextInt() | 1;
                            int keyB = random.nextInt() | 1;
                            InsnList repl = new InsnList();
                            String actualMode = (isArrayMode(mode) && s.length() > maxArray) ? overflowMode : mode;
                            int estimated = estimatedInstructions(s, actualMode);
                            if (isArrayMode(actualMode) && methodBudget > 0 && budgetUsed + estimated > methodBudget) {
                                actualMode = overflowMode;
                                estimated = estimatedInstructions(s, actualMode);
                            }
                            budgetUsed += estimated;
                            emitEncryptedString(repl, s, keyA, keyB, helperOwner, actualMode, indyNames.next());
                            if (usesIndy(actualMode) && ce.node.version < V1_7) ce.node.version = V1_7;
                            mn.instructions.insert(insn, repl);
                            mn.instructions.remove(insn);
                            changed++;
                        }
                    }
                    insn = next;
                }
            }
        }
        return changed;
    }


    private static int estimatedInstructions(String s, String mode) {
        if (isArrayMode(mode)) return Math.max(8, s.length() * 4 + 8);
        if (usesIndy(mode)) return 1;
        return 3;
    }

    public static boolean strongMode(ObfConfig config) {
        String mode = config.string("stringEncryption.mode", "array").toLowerCase(Locale.ROOT);
        return isArrayMode(mode);
    }

    public static void emitEncryptedString(InsnList il, String plain, int keyA, int keyB, String helperOwner, boolean strong) {
        emitEncryptedString(il, plain, keyA, keyB, helperOwner, strong ? "array" : "direct", "_");
    }

    public static void emitEncryptedString(InsnList il, String plain, int keyA, int keyB, String helperOwner, String mode) {
        emitEncryptedString(il, plain, keyA, keyB, helperOwner, mode, "_");
    }

    public static void emitEncryptedString(InsnList il, String plain, int keyA, int keyB, String helperOwner, String mode, String indyName) {
        if (isArrayMode(mode)) {
            emitArrayDecrypt(il, plain, keyA, keyB, helperOwner);
            return;
        }
        int key = keyA | 1;
        if (usesIndy(mode)) {
            Handle bsm = new Handle(H_INVOKESTATIC, helperOwner, "b", BSM_STRING_DESC, false);
            il.add(new InvokeDynamicInsnNode(indyName == null || indyName.isBlank() ? "_" : indyName, "()Ljava/lang/String;", bsm, xor(plain, key), key));
            return;
        }
        il.add(new LdcInsnNode(xor(plain, key)));
        il.add(Bytecode.pushInt(key));
        il.add(new MethodInsnNode(INVOKESTATIC, helperOwner, "d", "(Ljava/lang/String;I)Ljava/lang/String;", false));
    }

    public static void emitArrayDecrypt(InsnList il, String plain, int keyA, int keyB, String helperOwner) {
        int[] encoded = encodeArray(plain, keyA, keyB);
        il.add(Bytecode.pushInt(encoded.length));
        il.add(new IntInsnNode(NEWARRAY, T_INT));
        for (int i = 0; i < encoded.length; i++) {
            il.add(new InsnNode(DUP));
            il.add(Bytecode.pushInt(i));
            il.add(Bytecode.pushInt(encoded[i]));
            il.add(new InsnNode(IASTORE));
        }
        il.add(Bytecode.pushInt(keyA));
        il.add(Bytecode.pushInt(keyB));
        il.add(new MethodInsnNode(INVOKESTATIC, helperOwner, "x", "([III)Ljava/lang/String;", false));
    }

    public static int[] encodeArray(String plain, int keyA, int keyB) {
        int[] out = new int[plain.length()];
        int a = keyA;
        int b = keyB;
        for (int i = 0; i < plain.length(); i++) {
            a = a * 1664525 + 1013904223;
            b = Integer.rotateLeft(b ^ a, 5) + i * 0x9E3779B9;
            out[i] = plain.charAt(i) ^ a ^ b ^ (i * 31);
        }
        return out;
    }

    public static boolean usesIndy(String mode) {
        if (mode == null) return false;
        String m = mode.toLowerCase(Locale.ROOT);
        return m.equals("indy") || m.equals("invokedynamic") || m.equals("bootstrap");
    }

    public static boolean isArrayMode(String mode) {
        if (mode == null) return false;
        String m = mode.toLowerCase(Locale.ROOT);
        return m.equals("array") || m.equals("strong") || m.equals("hardened") || m.equals("int-array");
    }

    public static String xor(String s, int key) {
        char[] out = s.toCharArray();
        int x = key;
        for (int i = 0; i < out.length; i++) {
            x = x * 1103515245 + 12345;
            out[i] = (char) (out[i] ^ (x >>> 16));
        }
        return new String(out);
    }

    private boolean shouldEncrypt(String s, int minLen) {
        if (s.length() < minLen) return false;
        if (s.equals("plugin.yml") || s.equals("paper-plugin.yml")) return false;
        return !Wildcard.any(s, config.list("stringEncryption.skipLiterals"));
    }
}
