package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.NameGenerator;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.AnnotationNode;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.FieldNode;
import jdk.internal.org.objectweb.asm.tree.LdcInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public final class Renamer {
    private final ObfConfig config;
    private final NameGenerator packageNames;
    private final NameGenerator classNames;
    private final NameGenerator methodNames;
    private final NameGenerator fieldNames;
    private final Random random;

    public Renamer(ObfConfig config, long seed) {
        this.config = config;
        this.random = new Random(seed ^ 0xA11CE5EEDL);
        this.packageNames = new NameGenerator(
                config.string("renaming.packageStyle", config.string("renaming.style", "ascii")),
                config.integer("renaming.packageNameMinLength", 0),
                config.integer("renaming.packageNameMaxLength", 0),
                new Random(seed ^ 0x51A7E5EEDL));
        this.classNames = new NameGenerator(
                config.string("renaming.style", "ascii"),
                config.integer("renaming.classNameMinLength", 0),
                config.integer("renaming.classNameMaxLength", 0),
                new Random(seed ^ 0xC1A55E5EEDL));
        this.methodNames = new NameGenerator(
                config.string("renaming.memberStyle", config.string("renaming.style", "ascii")),
                config.integer("renaming.memberNameMinLength", 0),
                config.integer("renaming.memberNameMaxLength", 0),
                new Random(seed ^ 0xDEAD51A7L));
        this.fieldNames = new NameGenerator(
                config.string("renaming.memberStyle", config.string("renaming.style", "ascii")),
                config.integer("renaming.fieldNameMinLength", config.integer("renaming.memberNameMinLength", 0)),
                config.integer("renaming.fieldNameMaxLength", config.integer("renaming.memberNameMaxLength", 0)),
                new Random(seed ^ 0xF1E1D51A7L));
    }

    public MappingContext build(JarModel model) throws IOException {
        MappingContext ctx = new MappingContext();
        if (!config.enabled("renaming", true)) return ctx;
        loadExtraMappings(ctx, config.list("mappingShifting.files"));
        buildClassMap(model, ctx);
        buildMemberMap(model, ctx);
        patchStringClassReferences(model, ctx.classMap);
        patchStringMemberReferences(model, ctx.memberMap);
        return ctx;
    }

    private void buildClassMap(JarModel model, MappingContext ctx) {
        boolean renameClasses = config.bool("renaming.classes", true);
        if (!renameClasses) return;
        String base = cleanPackage(config.string("renaming.basePackage", "x"));
        String packageMode = config.string("renaming.packageMode", config.bool("renaming.flattenPackages", true) ? "flat" : "keep").toLowerCase(Locale.ROOT);
        Set<String> used = new HashSet<>(model.classes.keySet());
        used.addAll(ctx.classMap.values());
        for (ClassEntry ce : model.classes.values()) {
            ClassNode cn = ce.node;
            if (ctx.classMap.containsKey(cn.name)) continue;
            if (shouldKeepClass(cn)) continue;
            String newName;
            int guard = 0;
            do {
                newName = switch (packageMode) {
                    case "tree", "deep", "hierarchy", "hierarchical" -> deepName(base);
                    case "keep", "preserve" -> keepPackageName(cn.name, base);
                    default -> flatName(base);
                };
                guard++;
            } while (used.contains(newName) && guard < 10_000);
            used.add(newName);
            ctx.classMap.put(cn.name, newName);
        }
    }

    private String flatName(String base) {
        return classNames.nextInternalClass(base);
    }

    private String keepPackageName(String oldName, String fallbackBase) {
        int slash = oldName.lastIndexOf('/');
        String pkg = slash < 0 ? fallbackBase : oldName.substring(0, slash);
        if (pkg.isEmpty()) pkg = fallbackBase;
        return pkg.isEmpty() ? classNames.next() : pkg + "/" + classNames.next();
    }

    private String deepName(String base) {
        int min = Math.max(0, config.integer("renaming.packageDepthMin", 2));
        int max = Math.max(min, config.integer("renaming.packageDepthMax", 5));
        int depth = min + (max == min ? 0 : random.nextInt(max - min + 1));
        StringBuilder sb = new StringBuilder();
        if (!base.isEmpty()) sb.append(base);
        for (int i = 0; i < depth; i++) {
            if (sb.length() > 0) sb.append('/');
            sb.append(packageNames.next());
        }
        if (sb.length() > 0) sb.append('/');
        sb.append(classNames.next());
        return sb.toString();
    }

    private String cleanPackage(String p) {
        String out = p == null ? "" : p.replace('.', '/').trim();
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length() - 1);
        return out;
    }

    private void buildMemberMap(JarModel model, MappingContext ctx) {
        boolean renameMethods = config.bool("renaming.methods", true);
        boolean renameFields = config.bool("renaming.fields", true);
        for (ClassEntry ce : model.classes.values()) {
            ClassNode cn = ce.node;
            if (shouldKeepClass(cn)) continue;
            if (renameMethods) {
                Set<String> used = new HashSet<>();
                for (MethodNode mn : cn.methods) used.add(mn.name + mn.desc);
                for (MethodNode mn : cn.methods) {
                    if (shouldKeepMethod(cn, mn)) continue;
                    String n;
                    int guard = 0;
                    do {
                        n = methodNames.next();
                        guard++;
                    } while (used.contains(n + mn.desc) && guard < 10_000);
                    used.add(n + mn.desc);
                    ctx.memberMap.put(cn.name + "." + mn.name + mn.desc, n);
                }
            }
            if (renameFields) {
                Set<String> used = new HashSet<>();
                for (FieldNode fn : cn.fields) used.add(fn.name);
                for (FieldNode fn : cn.fields) {
                    if (shouldKeepField(cn, fn)) continue;
                    String n;
                    int guard = 0;
                    do {
                        n = fieldNames.next();
                        guard++;
                    } while (used.contains(n) && guard < 10_000);
                    used.add(n);
                    ctx.memberMap.put(cn.name + "." + fn.name, n);
                }
            }
        }
    }

    private boolean shouldKeepClass(ClassNode cn) {
        if (cn.name.equals("module-info") || cn.name.endsWith("/package-info")) return true;
        if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) return config.bool("renaming.keepAnnotations", true);
        if ((cn.access & Opcodes.ACC_ENUM) != 0 && config.bool("renaming.keepEnums", false)) return true;
        String fqn = cn.name.replace('/', '.');
        if (Wildcard.any(cn.name, config.list("renaming.keepClasses")) || Wildcard.any(fqn, config.list("renaming.keepClasses"))) return true;
        for (String p : config.list("renaming.keepPackages")) {
            String ip = p.replace('.', '/');
            if (cn.name.startsWith(ip)) return true;
        }
        return cn.name.startsWith("org/bukkit/") || cn.name.startsWith("net/minecraft/") || cn.name.startsWith("com/mojang/");
    }

    private boolean shouldKeepMethod(ClassNode cn, MethodNode mn) {
        if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) return true;
        if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) return true;
        if (config.bool("renaming.enumSafe", true) && isEnumMagicMethod(cn, mn)) return true;
        if (config.bool("renaming.keepNonPrivateMethods", true) && (mn.access & Opcodes.ACC_PRIVATE) == 0) return true;
        if (config.bool("renaming.minecraftSafe", true) && isMinecraftSensitiveMethod(mn)) return true;
        if (hasAnnotation(mn.visibleAnnotations, "Lorg/bukkit/event/EventHandler;") || hasAnnotation(mn.invisibleAnnotations, "Lorg/bukkit/event/EventHandler;")) {
            return config.bool("renaming.keepBukkitEventHandlers", false);
        }
        String sig = cn.name.replace('/', '.') + "." + mn.name + mn.desc;
        return Wildcard.any(sig, config.list("renaming.keepMethods")) || Wildcard.any(mn.name, config.list("renaming.keepMethodNames"));
    }

    private boolean isEnumMagicMethod(ClassNode cn, MethodNode mn) {
        if ((cn.access & Opcodes.ACC_ENUM) == 0) return false;
        // java.lang.Class#getEnumConstantsShared looks up the public static values() method
        // by its literal name. If an aggressive profile renames values(), EnumMap/EnumSet
        // can see a null enum universe and fail during plugin enable. Keep only the JVM/JDK
        // enum API surface while still allowing the enum class itself to be renamed.
        if (mn.name.equals("values") && mn.desc.equals("()[L" + cn.name + ";")) return true;
        if (mn.name.equals("valueOf") && mn.desc.equals("(Ljava/lang/String;)L" + cn.name + ";")) return true;
        return config.bool("renaming.keepEnumSyntheticMethods", false) && (mn.access & Opcodes.ACC_SYNTHETIC) != 0;
    }

    private boolean shouldKeepField(ClassNode cn, FieldNode fn) {
        if (fn.name.equals("serialVersionUID")) return true;
        if (config.bool("renaming.keepNonPrivateFields", true) && (fn.access & Opcodes.ACC_PRIVATE) == 0) return true;
        if ((cn.access & Opcodes.ACC_ENUM) != 0 && (fn.access & Opcodes.ACC_STATIC) != 0) return true;
        String sig = cn.name.replace('/', '.') + "." + fn.name;
        return Wildcard.any(sig, config.list("renaming.keepFields")) || Wildcard.any(fn.name, config.list("renaming.keepFieldNames"));
    }

    private boolean isMinecraftSensitiveMethod(MethodNode mn) {
        String n = mn.name;
        String d = mn.desc;
        if (n.equals("onEnable") && d.equals("()V")) return true;
        if (n.equals("onDisable") && d.equals("()V")) return true;
        if (n.equals("onLoad") && d.equals("()V")) return true;
        if (n.equals("onCommand") && d.equals("(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z")) return true;
        if (n.equals("onTabComplete") && d.equals("(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;")) return true;
        if (n.equals("onPluginMessageReceived") && d.equals("(Ljava/lang/String;Lorg/bukkit/entity/Player;[B)V")) return true;
        // Common Java/Bukkit interface callbacks. Keeping these avoids breaking interface dispatch in safe mode.
        return List.of("run", "call", "accept", "apply", "test", "get", "set", "compareTo", "equals", "hashCode", "toString", "serialize", "deserialize").contains(n);
    }

    private boolean hasAnnotation(List<AnnotationNode> anns, String desc) {
        if (anns == null) return false;
        for (AnnotationNode an : anns) if (desc.equals(an.desc)) return true;
        return false;
    }

    private void patchStringClassReferences(JarModel model, Map<String, String> classMap) {
        if (!config.bool("renaming.updateStringClassRefs", true) || classMap.isEmpty()) return;
        for (ClassEntry ce : model.classes.values()) {
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null) continue;
                for (var insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                        String mapped = classMap.get(s.replace('.', '/'));
                        if (mapped != null) {
                            ldc.cst = s.contains(".") ? mapped.replace('/', '.') : mapped;
                        }
                    }
                }
            }
        }
    }

    private void patchStringMemberReferences(JarModel model, Map<String, String> memberMap) {
        if (!config.bool("renaming.updateStringMemberRefs", false) || memberMap.isEmpty()) return;
        Map<String, String> unique = new java.util.LinkedHashMap<>();
        Set<String> duplicates = new HashSet<>();
        for (Map.Entry<String, String> e : memberMap.entrySet()) {
            String key = e.getKey();
            int dot = key.lastIndexOf('.');
            if (dot < 0) continue;
            String tail = key.substring(dot + 1);
            int desc = tail.indexOf('(');
            String oldName = desc >= 0 ? tail.substring(0, desc) : tail;
            if (oldName.isBlank() || oldName.startsWith("<")) continue;
            String previous = unique.putIfAbsent(oldName, e.getValue());
            if (previous != null && !previous.equals(e.getValue())) duplicates.add(oldName);
        }
        for (String d : duplicates) unique.remove(d);
        if (unique.isEmpty()) return;
        for (ClassEntry ce : model.classes.values()) {
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null) continue;
                for (var insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                        String mapped = unique.get(s);
                        if (mapped != null) ldc.cst = mapped;
                    }
                }
            }
        }
    }

    private void loadExtraMappings(MappingContext ctx, List<String> files) throws IOException {
        if (!config.enabled("mappingShifting", false)) return;
        for (String f : files) {
            if (f == null || f.isBlank()) continue;
            Path p = Path.of(f);
            if (!Files.exists(p)) continue;
            for (String raw : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                String line = raw.split("#", 2)[0].trim();
                if (line.isEmpty()) continue;
                String[] parts = line.contains("->") ? line.split("\\s*->\\s*") : line.split("\\s+");
                if (parts.length >= 2) {
                    ctx.classMap.put(parts[0].replace('.', '/'), parts[1].replace('.', '/'));
                }
            }
        }
    }
}
