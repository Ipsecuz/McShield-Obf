package dev.mcshield.obf.util;

import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.Type;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.InsnList;
import jdk.internal.org.objectweb.asm.tree.InsnNode;
import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import jdk.internal.org.objectweb.asm.tree.JumpInsnNode;
import jdk.internal.org.objectweb.asm.tree.LabelNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.TypeInsnNode;

public final class Bytecode implements Opcodes {
    private Bytecode() {}

    public static AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, value);
        if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, value);
        return new LdcInsnNode(value);
    }

    public static InsnList pushIntList(int value) {
        InsnList il = new InsnList();
        il.add(pushInt(value));
        return il;
    }

    public static int loadOpcode(Type t) {
        return switch (t.getSort()) {
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> ILOAD;
            case Type.FLOAT -> FLOAD;
            case Type.LONG -> LLOAD;
            case Type.DOUBLE -> DLOAD;
            default -> ALOAD;
        };
    }

    public static int storeOpcode(Type t) {
        return switch (t.getSort()) {
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> ISTORE;
            case Type.FLOAT -> FSTORE;
            case Type.LONG -> LSTORE;
            case Type.DOUBLE -> DSTORE;
            default -> ASTORE;
        };
    }

    public static int returnOpcode(Type t) {
        return switch (t.getSort()) {
            case Type.VOID -> RETURN;
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> IRETURN;
            case Type.FLOAT -> FRETURN;
            case Type.LONG -> LRETURN;
            case Type.DOUBLE -> DRETURN;
            default -> ARETURN;
        };
    }

    public static void box(InsnList il, Type t) {
        switch (t.getSort()) {
            case Type.BOOLEAN -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
            case Type.BYTE -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false));
            case Type.CHAR -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false));
            case Type.SHORT -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false));
            case Type.INT -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
            case Type.FLOAT -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
            case Type.LONG -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false));
            case Type.DOUBLE -> il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false));
            default -> {}
        }
    }

    public static void unboxOrCast(InsnList il, Type t) {
        switch (t.getSort()) {
            case Type.VOID -> il.add(new InsnNode(POP));
            case Type.BOOLEAN -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Boolean")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false)); }
            case Type.BYTE -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Byte")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false)); }
            case Type.CHAR -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Character")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false)); }
            case Type.SHORT -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Short")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false)); }
            case Type.INT -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Integer")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false)); }
            case Type.FLOAT -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Float")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false)); }
            case Type.LONG -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Long")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false)); }
            case Type.DOUBLE -> { il.add(new TypeInsnNode(CHECKCAST, "java/lang/Double")); il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false)); }
            case Type.ARRAY -> il.add(new TypeInsnNode(CHECKCAST, t.getDescriptor()));
            case Type.OBJECT -> il.add(new TypeInsnNode(CHECKCAST, t.getInternalName()));
            default -> {}
        }
    }

    /**
     * Legal opaque predicate. The earlier constant-vs-constant predicate decompiled too cleanly;
     * this variant depends on a runtime property lookup, but defaults to the same seed, so the
     * protected method keeps normal behaviour unless someone intentionally tampers with the JVM args.
     */
    public static InsnList opaqueThrowBlock(int seed) {
        InsnList il = new InsnList();
        LabelNode ok = new LabelNode();
        il.add(new LdcInsnNode("mcshield." + Integer.toHexString(seed)));
        il.add(pushInt(seed));
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Integer", "getInteger", "(Ljava/lang/String;Ljava/lang/Integer;)Ljava/lang/Integer;", false));
        il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false));
        il.add(pushInt(seed));
        il.add(new JumpInsnNode(IF_ICMPEQ, ok));
        il.add(new TypeInsnNode(NEW, "java/lang/IllegalStateException"));
        il.add(new InsnNode(DUP));
        il.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "()V", false));
        il.add(new InsnNode(ATHROW));
        il.add(ok);
        return il;
    }

    public static void addClassLiteral(InsnList il, Type type) {
        il.add(new LdcInsnNode(type));
    }

    public static int sizeOf(Type t) {
        return t == Type.LONG_TYPE || t == Type.DOUBLE_TYPE ? 2 : 1;
    }
}
