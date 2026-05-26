package dev.mcshield.obf.io;

import jdk.internal.org.objectweb.asm.tree.ClassNode;

public final class ClassEntry {
    public final String originalPath;
    public final byte[] originalBytes;
    public final ClassNode node;
    public boolean transformed = false;

    public ClassEntry(String originalPath, byte[] originalBytes, ClassNode node) {
        this.originalPath = originalPath;
        this.originalBytes = originalBytes;
        this.node = node;
    }
}
