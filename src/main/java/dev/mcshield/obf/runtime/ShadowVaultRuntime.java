package dev.mcshield.obf.runtime;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/** Runtime stage. */
public final class ShadowVaultRuntime {
    private static final String INIT_METHOD = "__mcshield$shadow$init";
    private static final IdentityHashMap<Object, Object> DELEGATES = new IdentityHashMap<>();
    private ShadowVaultRuntime() {}

    private static String dec(int[] data, int key) {
        char[] out = new char[data.length];
        int x = key ^ 0x5a17c0de;
        for (int i = 0; i < data.length; i++) {
            x = x * 1664525 + 1013904223;
            out[i] = (char)(data[i] ^ (x >>> 16) ^ (i * 131));
        }
        return new String(out);
    }

    public static void onLoad(Object host, int[] indexResource, int[] mainClass, int key) {
        onLoad(host, dec(indexResource, key ^ 0x2468ace), dec(mainClass, key ^ 0x13579bdf), key);
    }

    public static void onEnable(Object host, int[] indexResource, int[] mainClass, int key) {
        onEnable(host, dec(indexResource, key ^ 0x2468ace), dec(mainClass, key ^ 0x13579bdf), key);
    }

    public static void onDisable(Object host, int[] indexResource, int[] mainClass, int key) {
        onDisable(host, dec(indexResource, key ^ 0x2468ace), dec(mainClass, key ^ 0x13579bdf), key);
    }

    public static boolean onCommand(Object host, Object sender, Object command, String label, String[] args, int[] indexResource, int[] mainClass, int key) {
        return onCommand(host, sender, command, label, args, dec(indexResource, key ^ 0x2468ace), dec(mainClass, key ^ 0x13579bdf), key);
    }

    public static java.util.List<String> onTabComplete(Object host, Object sender, Object command, String alias, String[] args, int[] indexResource, int[] mainClass, int key) {
        return onTabComplete(host, sender, command, alias, args, dec(indexResource, key ^ 0x2468ace), dec(mainClass, key ^ 0x13579bdf), key);
    }

    public static void onLoad(Object host, String indexResource, String mainClass, int key) {
        Object delegate = ensure(host, indexResource, mainClass, key);
        copyPluginState(host, delegate);
        invoke(delegate, "onLoad");
    }

    public static void onEnable(Object host, String indexResource, String mainClass, int key) {
        Object delegate = ensure(host, indexResource, mainClass, key);
        copyPluginState(host, delegate);
        forceEnabled(delegate, true);
        registerVirtualCommands(host, indexResource, key);
        invoke(delegate, "onEnable");
        forceEnabled(delegate, true);
    }

    public static void onDisable(Object host, String indexResource, String mainClass, int key) {
        Object delegate = DELEGATES.get(host);
        if (delegate != null) {
            copyPluginState(host, delegate);
            forceEnabled(delegate, true);
            invoke(delegate, "onDisable");
            forceEnabled(delegate, false);
        }
    }

    public static boolean onCommand(Object host, Object sender, Object command, String label, String[] args, String indexResource, String mainClass, int key) {
        Object delegate = ensure(host, indexResource, mainClass, key);
        copyPluginState(host, delegate);
        forceEnabled(delegate, true);
        try {
            Method m = findMethod(delegate.getClass(), "onCommand",
                    Class.forName("org.bukkit.command.CommandSender"),
                    Class.forName("org.bukkit.command.Command"),
                    String.class, String[].class);
            if (m == null) return false;
            m.setAccessible(true);
            Object out = m.invoke(delegate, sender, command, label, args);
            return Boolean.TRUE.equals(out);
        } catch (Throwable t) {
            Throwable cause = t instanceof java.lang.reflect.InvocationTargetException && ((java.lang.reflect.InvocationTargetException)t).getCause() != null ? ((java.lang.reflect.InvocationTargetException)t).getCause() : t;
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException(cause);
        }
    }

    @SuppressWarnings("unchecked")
    public static java.util.List<String> onTabComplete(Object host, Object sender, Object command, String alias, String[] args, String indexResource, String mainClass, int key) {
        Object delegate = ensure(host, indexResource, mainClass, key);
        copyPluginState(host, delegate);
        forceEnabled(delegate, true);
        try {
            Method m = findMethod(delegate.getClass(), "onTabComplete",
                    Class.forName("org.bukkit.command.CommandSender"),
                    Class.forName("org.bukkit.command.Command"),
                    String.class, String[].class);
            if (m == null) return java.util.Collections.emptyList();
            m.setAccessible(true);
            Object out = m.invoke(delegate, sender, command, alias, args);
            if (out == null) return java.util.Collections.emptyList();
            if (out instanceof java.util.List) return (java.util.List<String>) out;
            return java.util.Collections.emptyList();
        } catch (Throwable t) {
            Throwable cause = t instanceof java.lang.reflect.InvocationTargetException && ((java.lang.reflect.InvocationTargetException)t).getCause() != null ? ((java.lang.reflect.InvocationTargetException)t).getCause() : t;
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException(cause);
        }
    }

    private static Method findMethod(Class<?> c, String name, Class<?>... types) {
        Class<?> x = c;
        while (x != null) {
            try { return x.getDeclaredMethod(name, types); } catch (NoSuchMethodException ignored) {}
            x = x.getSuperclass();
        }
        try { return c.getMethod(name, types); } catch (NoSuchMethodException ignored) {}
        return null;
    }

    private static synchronized Object ensure(Object host, String indexResource, String mainClass, int key) {
        Object existing = DELEGATES.get(host);
        if (existing != null) return existing;
        try {
            VaultLoader loader = new VaultLoader(host.getClass().getClassLoader(), indexResource, key);
            Class<?> main = loader.loadClass(mainClass);
            Object delegate = construct(main, host);
            copyPluginState(host, delegate);
            DELEGATES.put(host, delegate);
            return delegate;
        } catch (Throwable t) {
            throw new IllegalStateException("stage failed", t);
        }
    }

    private static Object construct(Class<?> type, Object host) throws Exception {
        try {
            Constructor<?> c = type.getDeclaredConstructor();
            c.setAccessible(true);
            return c.newInstance();
        } catch (Throwable ctorFailed) {
            Object unsafe = unsafeAllocate(type);
            copyPluginState(host, unsafe);
            invokeInitHook(unsafe);
            copyPluginState(host, unsafe);
            return unsafe;
        }
    }


    private static void invokeInitHook(Object target) {
        if (target == null) return;
        try {
            Method m = target.getClass().getDeclaredMethod(INIT_METHOD);
            m.setAccessible(true);
            m.invoke(target);
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) {
            Throwable cause = t instanceof java.lang.reflect.InvocationTargetException && ((java.lang.reflect.InvocationTargetException)t).getCause() != null ? ((java.lang.reflect.InvocationTargetException)t).getCause() : t;
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException(cause);
        }
    }

    private static Object unsafeAllocate(Class<?> type) throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field f = unsafeClass.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Object unsafe = f.get(null);
        Method m = unsafeClass.getMethod("allocateInstance", Class.class);
        return m.invoke(unsafe, type);
    }

    private static void copyPluginState(Object host, Object delegate) {
        if (host == null || delegate == null) return;
        Class<?> hc = host.getClass();
        Class<?> dc = delegate.getClass();
        while (hc != null && dc != null) {
            copyDeclaredFields(hc, host, dc, delegate);
            hc = hc.getSuperclass();
            dc = dc.getSuperclass();
        }
        // Also copy Bukkit JavaPlugin superclass fields by matching names where hierarchy differs.
        Class<?> h = host.getClass();
        while (h != null) {
            Class<?> d = delegate.getClass();
            while (d != null) {
                copyDeclaredFields(h, host, d, delegate);
                d = d.getSuperclass();
            }
            h = h.getSuperclass();
        }
    }

    private static void forceEnabled(Object plugin, boolean enabled) {
        if (plugin == null) return;
        Class<?> c = plugin.getClass();
        while (c != null) {
            for (Field f : c.getDeclaredFields()) {
                try {
                    if (f.getType() == boolean.class && (f.getName().equals("isEnabled") || f.getName().equals("enabled"))) {
                        f.setAccessible(true);
                        f.setBoolean(plugin, enabled);
                    }
                } catch (Throwable ignored) {}
            }
            c = c.getSuperclass();
        }
    }

    private static void copyDeclaredFields(Class<?> hc, Object host, Class<?> dc, Object delegate) {
        for (Field hf : hc.getDeclaredFields()) {
            try {
                if (java.lang.reflect.Modifier.isStatic(hf.getModifiers())) continue;
                Field df;
                try { df = dc.getDeclaredField(hf.getName()); } catch (NoSuchFieldException e) { continue; }
                if (java.lang.reflect.Modifier.isStatic(df.getModifiers())) continue;
                hf.setAccessible(true); df.setAccessible(true);
                if (df.getType().isAssignableFrom(hf.getType()) || hf.getType().isAssignableFrom(df.getType())) df.set(delegate, hf.get(host));
            } catch (Throwable ignored) {}
        }
    }

    private static void invoke(Object target, String name) {
        try {
            Method m = target.getClass().getMethod(name);
            m.setAccessible(true);
            m.invoke(target);
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) {
            Throwable cause = t instanceof java.lang.reflect.InvocationTargetException && ((java.lang.reflect.InvocationTargetException)t).getCause() != null ? ((java.lang.reflect.InvocationTargetException)t).getCause() : t;
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException(cause);
        }
    }

    private static void registerVirtualCommands(Object host, String indexResource, int key) {
        try {
            List<String> names = readCommands(host.getClass().getClassLoader(), indexResource, key);
            if (names.isEmpty()) return;
            Object server = Class.forName("org.bukkit.Bukkit").getMethod("getServer").invoke(null);
            Method getCommandMap = server.getClass().getMethod("getCommandMap");
            Object commandMap = getCommandMap.invoke(server);
            Class<?> pluginClass = Class.forName("org.bukkit.plugin.Plugin");
            Class<?> pluginCommandClass = Class.forName("org.bukkit.command.PluginCommand");
            Constructor<?> ctor = pluginCommandClass.getDeclaredConstructor(String.class, pluginClass);
            ctor.setAccessible(true);
            Method register = commandMap.getClass().getMethod("register", String.class, Class.forName("org.bukkit.command.Command"));
            String prefix = String.valueOf(host.getClass().getMethod("getName").invoke(host)).toLowerCase(java.util.Locale.ROOT);
            for (String n : names) {
                try {
                    Object cmd = ctor.newInstance(n, host);
                    register.invoke(commandMap, prefix, cmd);
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {}
    }

    private static List<String> readCommands(ClassLoader cl, String indexResource, int key) throws Exception {
        DataInputStream in = new DataInputStream(new java.io.ByteArrayInputStream(readVaultIndex(cl, indexResource, key)));
        if (in.readInt() != 0x4d535631) return new ArrayList<>();
        int classCount = in.readInt();
        for (int i = 0; i < classCount; i++) { in.readUTF(); in.readUTF(); }
        int cmdCount = in.readInt();
        List<String> out = new ArrayList<>();
        for (int i = 0; i < cmdCount; i++) {
            String v = in.readUTF();
            if (v != null && !v.isEmpty()) out.add(v);
        }
        return out;
    }

    private static byte[] readVaultIndex(ClassLoader cl, String indexResource, int key) throws Exception {
        try (InputStream in = cl.getResourceAsStream(indexResource)) {
            if (in == null) throw new IllegalStateException("missing vault index " + indexResource);
            return xor(in.readAllBytes(), key ^ 0x51f15e);
        }
    }

    private static byte[] xor(byte[] in, int key) {
        byte[] out = new byte[in.length];
        int s = key;
        for (int i = 0; i < in.length; i++) {
            s = s * 1103515245 + 12345;
            out[i] = (byte) (in[i] ^ (s >>> 16));
        }
        return out;
    }

    private static final class VaultLoader extends ClassLoader {
        private final Map<String, Entry> entries = new HashMap<>();
        private final int key;

        VaultLoader(ClassLoader parent, String indexResource, int key) throws Exception {
            super(parent);
            this.key = key;
            parse(parent, indexResource, key);
        }

        private void parse(ClassLoader parent, String indexResource, int key) throws Exception {
            DataInputStream in = new DataInputStream(new java.io.ByteArrayInputStream(readVaultIndex(parent, indexResource, key)));
            if (in.readInt() != 0x4d535631) throw new IllegalStateException();
            int classCount = in.readInt();
            for (int i = 0; i < classCount; i++) {
                entries.put(in.readUTF(), new Entry(in.readUTF()));
            }
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded != null) return loaded;
                if (entries.containsKey(name)) {
                    Class<?> c = findClass(name);
                    if (resolve) resolveClass(c);
                    return c;
                }
                return super.loadClass(name, resolve);
            }
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            Entry e = entries.get(name);
            if (e == null) throw new ClassNotFoundException(name);
            try (InputStream in = getParent().getResourceAsStream(e.resource)) {
                if (in == null) throw new ClassNotFoundException(name + " resource missing");
                byte[] enc = in.readAllBytes();
                byte[] gz = xor(enc, key ^ name.hashCode());
                byte[] bytes = gunzip(gz);
                int idx = name.lastIndexOf('.');
                if (idx > 0) {
                    String pkg = name.substring(0, idx);
                    if (getDefinedPackage(pkg) == null) {
                        try { definePackage(pkg, null, null, null, null, null, null, null); } catch (IllegalArgumentException ignored) {}
                    }
                }
                return defineClass(name, bytes, 0, bytes.length);
            } catch (Throwable t) {
                ClassNotFoundException cnf = new ClassNotFoundException(name);
                cnf.initCause(t);
                throw cnf;
            }
        }
    }

    private static byte[] gunzip(byte[] data) throws Exception {
        try (GZIPInputStream gis = new GZIPInputStream(new java.io.ByteArrayInputStream(data)); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = gis.read(buf)) >= 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    private static final class Entry { final String resource; Entry(String resource) { this.resource = resource; } }
}
