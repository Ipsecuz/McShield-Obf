package dev.mcshield.obf.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

public final class Strings {
    private Strings() {}

    public static String d(String s, int key) {
        char[] out = s.toCharArray();
        int x = key;
        for (int i = 0; i < out.length; i++) {
            x = x * 1103515245 + 12345;
            out[i] = (char) (out[i] ^ (x >>> 16));
        }
        return new String(out);
    }

    public static String x(int[] data, int keyA, int keyB) {
        char[] out = new char[data.length];
        int a = keyA;
        int b = keyB;
        for (int i = 0; i < data.length; i++) {
            a = a * 1664525 + 1013904223;
            b = Integer.rotateLeft(b ^ a, 5) + i * 0x9E3779B9;
            out[i] = (char) (data[i] ^ a ^ b ^ (i * 31));
        }
        return new String(out);
    }

    public static CallSite b(MethodHandles.Lookup lookup, String name, MethodType type, String s, int key) {
        MethodHandle mh = MethodHandles.constant(String.class, d(s, key)).asType(type);
        return new ConstantCallSite(mh);
    }

    public static CallSite c(MethodHandles.Lookup lookup, String name, MethodType type, int[] data, int keyA, int keyB) {
        MethodHandle mh = MethodHandles.constant(String.class, x(data, keyA, keyB)).asType(type);
        return new ConstantCallSite(mh);
    }
}
