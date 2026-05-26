package dev.mcshield.obf.runtime;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class Ref {
    private Ref() {}

    public static Object s(String owner, String name, Class<?>[] types, Object[] args) {
        try {
            Class<?> c = Class.forName(owner);
            Method m = findMethod(c, name, types, true);
            return m.invoke(null, args);
        } catch (InvocationTargetException e) {
            throw rethrow(e.getCause());
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static Object v(Object target, String name, Class<?>[] types, Object[] args) {
        if (target == null) throw new NullPointerException("target");
        try {
            Method m = findMethod(target.getClass(), name, types, false);
            return m.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw rethrow(e.getCause());
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static Object f(Object target, String owner, String name) {
        if (target == null) throw new NullPointerException("target");
        try {
            Field field = findField(Class.forName(owner), name);
            return field.get(target);
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void p(Object target, String owner, String name, Object value) {
        if (target == null) throw new NullPointerException("target");
        try {
            Field field = findField(Class.forName(owner), name);
            field.set(target, value);
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static Method findMethod(Class<?> c, String name, Class<?>[] types, boolean requireStatic) throws NoSuchMethodException {
        try {
            Method m = c.getMethod(name, types);
            try { m.setAccessible(true); } catch (Throwable ignored) {}
            return m;
        } catch (NoSuchMethodException ignored) {
            // fall through to declared-method walk
        }
        Class<?> x = c;
        while (x != null) {
            try {
                Method m = x.getDeclaredMethod(name, types);
                try { m.setAccessible(true); } catch (Throwable ignored) {}
                return m;
            } catch (NoSuchMethodException ignored) {
                x = x.getSuperclass();
            }
        }
        throw new NoSuchMethodException(c.getName() + "." + name);
    }

    private static Field findField(Class<?> c, String name) throws NoSuchFieldException {
        Class<?> x = c;
        while (x != null) {
            try {
                Field f = x.getDeclaredField(name);
                try { f.setAccessible(true); } catch (Throwable ignored) {}
                return f;
            } catch (NoSuchFieldException ignored) {
                x = x.getSuperclass();
            }
        }
        throw new NoSuchFieldException(c.getName() + "." + name);
    }

    private static RuntimeException rethrow(Throwable cause) {
        if (cause instanceof RuntimeException re) return re;
        if (cause instanceof Error er) throw er;
        return new RuntimeException(cause);
    }
}
