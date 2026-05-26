package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.Type;
import jdk.internal.org.objectweb.asm.tree.*;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Real shell/delegate mode.
 *
 * plugin.yml points at a small public JavaPlugin shell (boot.Pivot). The original
 * plugin main is converted into a normal delegate class, so following the
 * superclass chain from plugin.yml no longer reaches the class containing the
 * lifecycle/business logic. The shell owns the real Bukkit JavaPlugin context and
 * forwards lifecycle/command calls into the delegate.
 *
 * This mode is intentionally conservative: it only rewrites the main class and
 * common JavaPlugin API usages. It is meant for plugins where ShadowVault is too
 * aggressive but ShadowBoot still exposes the real main through inheritance.
 */
public final class ShellDelegate implements Opcodes {
    private static final String JAVA_PLUGIN = "org/bukkit/plugin/java/JavaPlugin";
    private final ObfConfig config;

    public ShellDelegate(ObfConfig config) {
        this.config = config;
    }

    public Result apply(JarModel model, MappingContext mapping, Map<String, byte[]> generatedClasses, Map<String, byte[]> generatedResources) {
        if (!config.enabled("shellDelegate", false)) return Result.disabled();
        if (model.pluginMainFqn == null || model.pluginMainFqn.isBlank()) return requiredSkip("plugin.yml main not found");
        String yamlMain = model.pluginMainFqn.replace('.', '/');

        // ShellDelegate hardening: do not require plugin.yml main to be the real JavaPlugin class.
        // If a previous profile already produced a proxy chain, follow the superclass chain and
        // cut the actual JavaPlugin leaf into a delegate. This prevents accidentally shipping
        // plugin.yml -> proxy -> real main again when users obfuscate an already-proxied build.
        String targetMain = findJavaPluginLeaf(model, yamlMain);
        if (targetMain == null) return requiredSkip("could not find JavaPlugin leaf from " + yamlMain);
        ClassEntry ce = model.classes.get(targetMain);
        if (ce == null) return requiredSkip("main class not found: " + targetMain);
        if (!JAVA_PLUGIN.equals(ce.node.superName)) return requiredSkip("target main does not directly extend JavaPlugin: " + targetMain + " -> " + ce.node.superName);
        if (find(ce.node, "<init>", "()V") == null) return requiredSkip("target main has no no-arg constructor: " + targetMain);

        String publicOwner = owner(config.string("shellDelegate.publicMain", "boot.Pivot"));
        if (publicOwner.isBlank()) publicOwner = "boot/Pivot";
        publicOwner = unique(publicOwner, model, generatedClasses);

        String ctxField = config.string("shellDelegate.contextField", "__mcs$c");
        String bindMethod = config.string("shellDelegate.bindMethod", "__mcs$b");
        String ensureMethod = config.string("shellDelegate.ensureMethod", "__mcs$e");
        String delegateField = config.string("shellDelegate.delegateField", "__mcs$d");
        String decoderMethod = config.string("shellDelegate.decoderMethod", "__mcs$s");
        String invokerMethod = config.string("shellDelegate.invokerMethod", "__mcs$i");
        if (config.bool("shellDelegate.randomizeBridgeNames", true)) {
            long s0 = config.seed();
            ctxField = bridgeName("f", targetMain + ":ctx:" + s0, 18);
            bindMethod = bridgeName("b", targetMain + ":bind:" + s0, 18);
            ensureMethod = bridgeName("e", targetMain + ":ensure:" + s0, 18);
            delegateField = bridgeName("d", targetMain + ":delegate:" + s0, 18);
            decoderMethod = bridgeName("s", targetMain + ":decode:" + s0, 18);
            invokerMethod = bridgeName("i", targetMain + ":invoke:" + s0, 18);
        } else if (config.bool("shellDelegate.randomizeBindMethod", true)) {
            bindMethod = "__mcs$" + Integer.toHexString((targetMain + ":bind").hashCode()).replace('-', 'n');
        }

        transformMainToDelegate(ce.node, targetMain, ctxField, bindMethod);
        Map<String, String> bridgeAliases = renameDelegateBridgeMethods(model, ce.node, targetMain);
        int sensitiveRenamed = renameSensitiveDelegateMethods(model, ce.node, targetMain, bridgeAliases);
        if (sensitiveRenamed > 0) {
            System.out.println("[mcshield] shellDelegate renamed sensitive delegate methods=" + sensitiveRenamed);
        }
        ce.transformed = true;

        String runtimeDelegate = mapping.fullMap().getOrDefault(targetMain, targetMain);
        List<CommandSpec> virtualCommands = collectVirtualCommands(model);
        List<PermissionSpec> virtualPermissions = collectVirtualPermissions(model);
        generatedClasses.put(publicOwner, generateShell(publicOwner, targetMain, runtimeDelegate, delegateField, ensureMethod, bindMethod, decoderMethod, invokerMethod, ce.node, bridgeAliases, virtualCommands, virtualPermissions));
        Map<String, byte[]> delegateDecoys = generateDelegateDecoys(model, generatedClasses, targetMain, runtimeDelegate, ce.node, ctxField, bindMethod);
        generatedClasses.putAll(delegateDecoys);
        if (!delegateDecoys.isEmpty()) {
            System.out.println("[mcshield] shellDelegate generated delegate decoys=" + delegateDecoys.size());
        }
        generatedResources.putAll(metadata(publicOwner));

        Map<String, String> yaml = new LinkedHashMap<>(mapping.fullMap());
        yaml.put(yamlMain, publicOwner);
        yaml.put(targetMain, publicOwner); // safety if plugin.yml already pointed at the leaf
        if (!yamlMain.equals(targetMain)) {
            System.out.println("[mcshield] shellDelegate cut proxy chain: " + yamlMain.replace('/', '.') + " -> " + targetMain.replace('/', '.'));
        }
        return new Result(true, publicOwner, targetMain, yaml);
    }

    private String bridgeName(String prefix, String material, int len) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(prefix == null || prefix.isBlank() ? "x" : prefix.replaceAll("[^A-Za-z]", "x"));
        long x = material.hashCode() * 0x9e3779b97f4a7c15L ^ 0x6a09e667f3bcc909L;
        while (sb.length() < len) {
            x ^= (x << 13);
            x ^= (x >>> 7);
            x ^= (x << 17);
            sb.append(alphabet.charAt((int)Math.floorMod(x, alphabet.length())));
        }
        return sb.toString();
    }

    private boolean isShellSyntheticName(String name) {
        if (name == null) return false;
        if (name.startsWith("__mcs$")) return true;
        return name.matches("[fbeids][a-z]{12,}");
    }

    private Result requiredSkip(String reason) {
        String msg = "[mcshield] shellDelegate skipped: " + reason;
        if (config.bool("shellDelegate.required", false)) throw new IllegalStateException(msg);
        System.err.println(msg);
        return Result.disabled();
    }

    private String findJavaPluginLeaf(JarModel model, String start) {
        String cur = start;
        java.util.HashSet<String> seen = new java.util.HashSet<>();
        int guard = Math.max(8, config.integer("shellDelegate.maxSuperDepth", 512));
        String lastJavaPluginChild = null;
        while (cur != null && !cur.isBlank() && seen.add(cur) && guard-- > 0) {
            ClassEntry ce = model.classes.get(cur);
            if (ce == null) return lastJavaPluginChild;
            if (JAVA_PLUGIN.equals(ce.node.superName)) return cur;
            if (ce.node.superName == null || ce.node.superName.startsWith("java/")) return lastJavaPluginChild;
            cur = ce.node.superName;
        }
        return lastJavaPluginChild;
    }

    private void transformMainToDelegate(ClassNode cn, String owner, String ctxField, String bindMethod) {
        cn.access &= ~ACC_FINAL;
        cn.superName = "java/lang/Object";
        cn.sourceFile = config.string("shellDelegate.delegateSourceFile", "module.c");
        cn.sourceDebug = null;
        cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_TRANSIENT | ACC_SYNTHETIC, ctxField, "L" + JAVA_PLUGIN + ";", null, null));
        rewriteConstructors(cn, owner);
        rewriteJavaPluginCalls(cn, owner, ctxField);
        rewriteGetCommandLiterals(cn);
        addBind(cn, ctxField, bindMethod);
        addContextHelpers(cn, ctxField);
        int enc = encryptDelegateStrings(cn);
        if (enc > 0) System.out.println("[mcshield] shellDelegate encrypted delegate strings=" + enc);
        padRealDelegate(cn, owner);
        if (config.bool("shellDelegate.stripDebugLocals", true)) stripLocalVariableMetadata(cn);
    }

    private int encryptDelegateStrings(ClassNode cn) {
        if (!config.bool("shellDelegate.encryptDelegateStrings", false)) return 0;
        int minLen = Math.max(0, config.integer("shellDelegate.delegateStringMinLength", 1));
        String mode = config.string("shellDelegate.delegateStringMode", "direct");
        String helperOwner = runtimeStringsOwner();
        int changed = 0;
        int seed = (cn.name + ":delegate-strings").hashCode();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            // avoid touching synthetic bind/context wrappers; keep those stable and simple
            if (isShellSyntheticName(mn.name) && !config.bool("shellDelegate.encryptSyntheticHelpers", false)) continue;
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String plain) {
                    if (plain.length() >= minLen && !skipDelegateString(plain)) {
                        int k1 = (seed * 1103515245 + plain.hashCode()) | 1;
                        int k2 = (Integer.rotateLeft(seed ^ plain.length(), 11) + 0x5f3759df) | 1;
                        InsnList repl = new InsnList();
                        StringEncryptor.emitEncryptedString(repl, plain, k1, k2, helperOwner, mode, "_" + Integer.toHexString(k1 ^ k2));
                        if (StringEncryptor.usesIndy(mode) && cn.version < V1_7) cn.version = V1_7;
                        mn.instructions.insert(insn, repl);
                        mn.instructions.remove(insn);
                        changed++;
                    }
                }
                insn = next;
            }
        }
        return changed;
    }

    private boolean skipDelegateString(String plain) {
        if (plain == null) return true;
        if (plain.equals("plugin.yml") || plain.equals("paper-plugin.yml")) return true;
        if (plain.startsWith("__mcs$") || plain.startsWith("boot.")) return true;
        return dev.mcshield.obf.util.Wildcard.any(plain, config.list("shellDelegate.delegateStringSkipLiterals"));
    }

    private String runtimeStringsOwner() {
        String pkg = config.string("runtime.package", "rt.mcshield").replace('.', '/');
        while (pkg.startsWith("/")) pkg = pkg.substring(1);
        while (pkg.endsWith("/")) pkg = pkg.substring(0, pkg.length() - 1);
        String leaf = config.string("runtime.stringsClass", "Strings").replace('.', '/');
        while (leaf.startsWith("/")) leaf = leaf.substring(1);
        return pkg.isBlank() ? leaf : pkg + "/" + leaf;
    }

    private void padRealDelegate(ClassNode cn, String owner) {
        if (!config.bool("shellDelegate.padRealDelegate", true)) return;
        int targetFields = Math.max(0, config.integer("shellDelegate.realDelegateFieldTarget", config.integer("shellDelegate.delegateDecoys.fieldCount", 0)));
        int targetMethods = Math.max(0, config.integer("shellDelegate.realDelegateMethodTarget", config.integer("shellDelegate.delegateDecoys.methodCount", 0)));
        int fieldAdded = 0;
        while (cn.fields.size() < targetFields) {
            String name = uniqueFieldName(cn, "b" + Integer.toHexString((owner.hashCode() ^ cn.fields.size() * 0x45d9f3b)));
            String[] descs = {"Ljava/lang/Object;", "Ljava/util/Map;", "Ljava/util/List;", "Ljava/lang/String;", "I", "Z", "J"};
            cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_SYNTHETIC, name, descs[Math.floorMod(owner.hashCode() + cn.fields.size(), descs.length)], null, null));
            fieldAdded++;
        }
        int methodAdded = 0;
        int surfaceRepeat = Math.max(1, config.integer("shellDelegate.realDelegateSurfaceRepeats", 2));
        String[][] surface = delegateSurfaceMethods();
        int guard = 0;
        while (cn.methods.size() < targetMethods && guard++ < targetMethods * 3 + 200) {
            String[] m = surface[Math.floorMod(cn.methods.size() + owner.hashCode(), surface.length)];
            String base = m[0] + Integer.toHexString((owner + cn.methods.size() + m[0]).hashCode()).replace('-', 'n');
            String name = (methodAdded < surface.length * surfaceRepeat) ? base : "m" + Integer.toHexString(owner.hashCode() ^ cn.methods.size() * 0x7f4a7c15);
            addDecoyMethod(cn, uniqueMethodName(cn, name, m[1]), m[1], owner.hashCode() ^ cn.methods.size());
            methodAdded++;
        }
        if (fieldAdded + methodAdded > 0) {
            System.out.println("[mcshield] shellDelegate padded real delegate fields=" + fieldAdded + ", methods=" + methodAdded);
        }
    }

    private String[][] delegateSurfaceMethods() {
        return new String[][] {
                {"onLoad", "()V"}, {"onEnable", "()V"}, {"onDisable", "()V"},
                {"reloadPlugin", "()V"}, {"checkLicense", "()Z"}, {"createHttpClient", "()Ljava/lang/Object;"},
                {"processSuccessPayment", "(Ljava/lang/Object;)V"}, {"processManualTopup", "(Ljava/lang/Object;)V"},
                {"handleCardResponse", "(Ljava/lang/Object;)V"}, {"giveCardReward", "(Ljava/lang/Object;)V"},
                {"spawnSuccessFirework", "(Ljava/lang/Object;)V"}, {"resetTopNap", "()V"}, {"isLicenseValid", "()Z"},
                {"calculateFinalPoints", "(J)I"}, {"calculateBankBasePoints", "(J)I"}, {"calculateBonusPoints", "(J)I"},
                {"isPromotionActive", "()Z"}, {"dispatchConsoleCommand", "(Ljava/lang/String;)V"}, {"broadcast", "(Ljava/lang/String;)V"},
                {"sendActionBar", "(Ljava/lang/Object;Ljava/lang/String;)V"}, {"openJsonPostConnection", "(Ljava/lang/String;)Ljava/lang/Object;"},
                {"getInstance", "()Ljava/lang/Object;"}, {"getPlatformScheduler", "()Ljava/lang/Object;"},
                {"getLanguageManager", "()Ljava/lang/Object;"}, {"getDatabaseManager", "()Ljava/lang/Object;"},
                {"getMilestoneManager", "()Ljava/lang/Object;"}, {"getBankPaymentManager", "()Ljava/lang/Object;"},
                {"getLogManager", "()Ljava/lang/Object;"}, {"getAdminGUIManager", "()Ljava/lang/Object;"},
                {"getCardSessionManager", "()Ljava/lang/Object;"}, {"getCardListener", "()Ljava/lang/Object;"},
                {"getCardRateManager", "()Ljava/lang/Object;"}, {"getMilestoneGuiManager", "()Ljava/lang/Object;"},
                {"getPaymentGuiManager", "()Ljava/lang/Object;"}, {"getPendingCards", "()Ljava/util/Map;"},
                {"getCardRewardRatio", "()I"}, {"getCardRewardCommands", "()Ljava/util/List;"}, {"getCardProviderName", "()Ljava/lang/String;"},
                {"getCommand", "(Ljava/lang/String;)Lorg/bukkit/command/PluginCommand;"}, {"getServer", "()Lorg/bukkit/Server;"},
                {"getLogger", "()Ljava/util/logging/Logger;"}, {"getConfig", "()Lorg/bukkit/configuration/file/FileConfiguration;"},
                {"saveDefaultConfig", "()V"}, {"saveResource", "(Ljava/lang/String;Z)V"}, {"getResource", "(Ljava/lang/String;)Ljava/io/InputStream;"},
                {"bank", "()V"}, {"napthe", "()V"}, {"topnap", "()V"}, {"lichsunap", "()V"}, {"mocnap", "()V"},
                {"korapayments", "()V"}, {"confirmcard", "()V"}, {"cancelcard", "()V"}
        };
    }

    private String[][] bridgeWrapperSurface() {
        return new String[][] {
                {"getCommand", "(Ljava/lang/String;)Lorg/bukkit/command/PluginCommand;"},
                {"getServer", "()Lorg/bukkit/Server;"},
                {"getLogger", "()Ljava/util/logging/Logger;"},
                {"getName", "()Ljava/lang/String;"},
                {"getDataFolder", "()Ljava/io/File;"},
                {"getDescription", "()Lorg/bukkit/plugin/PluginDescriptionFile;"},
                {"getConfig", "()Lorg/bukkit/configuration/file/FileConfiguration;"},
                {"isEnabled", "()Z"},
                {"reloadConfig", "()V"},
                {"saveConfig", "()V"},
                {"saveDefaultConfig", "()V"},
                {"getResource", "(Ljava/lang/String;)Ljava/io/InputStream;"},
                {"saveResource", "(Ljava/lang/String;Z)V"}
        };
    }

    private int mixedDecoyFieldCount(int base, int idx) {
        if (!config.bool("shellDelegate.delegateDecoys.mixedSizes", true)) return base;
        int[] bins = {18, 24, 64, 96, 128, 129, 140};
        return Math.max(8, bins[Math.floorMod(idx * 31 + base, bins.length)]);
    }

    private int mixedDecoyMethodCount(int base, int idx) {
        if (!config.bool("shellDelegate.delegateDecoys.mixedSizes", true)) return base;
        int[] bins = {88, 96, 180, 240, 360, 420, 421, 430};
        return Math.max(32, bins[Math.floorMod(idx * 17 + base, bins.length)]);
    }

    private void stripLocalVariableMetadata(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (mn.localVariables != null) mn.localVariables.clear();
            if (mn.visibleLocalVariableAnnotations != null) mn.visibleLocalVariableAnnotations.clear();
            if (mn.invisibleLocalVariableAnnotations != null) mn.invisibleLocalVariableAnnotations.clear();
        }
    }

    private Map<String, String> renameDelegateBridgeMethods(JarModel model, ClassNode cn, String owner) {
        Map<String, String> aliases = new HashMap<>();
        if (!config.bool("shellDelegate.renameLifecycleMethods", true)) return aliases;
        aliasMethod(model, cn, owner, aliases, "onLoad", "()V", "l");
        aliasMethod(model, cn, owner, aliases, "onEnable", "()V", "e");
        aliasMethod(model, cn, owner, aliases, "onDisable", "()V", "d");
        aliasMethod(model, cn, owner, aliases, "onCommand", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z", "c");
        aliasMethod(model, cn, owner, aliases, "onTabComplete", "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;", "t");
        return aliases;
    }

    private void aliasMethod(JarModel model, ClassNode cn, String owner, Map<String, String> aliases, String name, String desc, String salt) {
        MethodNode mn = find(cn, name, desc);
        if (mn == null) return;
        String alias = uniqueMethodName(cn, "m" + Integer.toHexString((owner + name + desc + salt).hashCode()).replace('-', 'n'), desc);
        mn.name = alias;
        aliases.put(key(name, desc), alias);
        rewriteCallsTo(model, owner, name, desc, alias);
    }

    private int renameSensitiveDelegateMethods(JarModel model, ClassNode cn, String owner, Map<String, String> aliases) {
        if (!config.bool("shellDelegate.renameSensitiveMethods", true)) return 0;
        Set<String> names = new HashSet<>(config.list("shellDelegate.sensitiveMethodNames"));
        if (names.isEmpty()) {
            String[] defaults = {"reloadPlugin", "checkLicense", "createHttpClient", "processSuccessPayment", "processManualTopup", "handleCardResponse", "giveCardReward", "getPendingCards", "getBankPaymentManager", "isLicenseValid", "resetTopNap", "spawnSuccessFirework"};
            for (String n : defaults) names.add(n);
        }
        int changed = 0;
        for (MethodNode mn : cn.methods) {
            if (mn.name.startsWith("<")) continue;
            if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
            if (!names.contains(mn.name)) continue;
            // API safety: do not rename public/protected API-style methods by default.
            // KoraPayments has cross-class calls like getBankPaymentManager(); renaming these
            // without complete post-remap call repair can cause NoSuchMethodError at runtime.
            if (config.bool("shellDelegate.keepNonPrivateSensitiveMethods", true)
                    && (mn.access & (ACC_PUBLIC | ACC_PROTECTED)) != 0) continue;
            // Getter/setter/is-style methods are commonly used as internal API between classes.
            // Keep them stable unless explicitly disabled in config. Decoys still add noisy names.
            if (config.bool("shellDelegate.keepAccessorSensitiveMethods", true)
                    && (mn.name.startsWith("get") || mn.name.startsWith("set") || mn.name.startsWith("is"))) continue;
            if (aliases.containsKey(key(mn.name, mn.desc))) continue;
            String old = mn.name;
            String alias = uniqueMethodName(cn, "q" + Integer.toHexString((owner + old + mn.desc + ":s").hashCode()).replace('-', 'n'), mn.desc);
            mn.name = alias;
            rewriteCallsTo(model, owner, old, mn.desc, alias);
            changed++;
        }
        return changed;
    }

    private String uniqueMethodName(ClassNode cn, String base, String desc) {
        String n = base;
        int i = 0;
        while (find(cn, n, desc) != null) n = base + Integer.toHexString(++i);
        return n;
    }

    private void rewriteCallsTo(JarModel model, String owner, String oldName, String desc, String newName) {
        for (ClassEntry ce : model.classes.values()) {
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode mi && owner.equals(mi.owner) && oldName.equals(mi.name) && desc.equals(mi.desc)) {
                        mi.name = newName;
                    }
                }
            }
        }
    }

    private String alias(Map<String, String> aliases, String name, String desc) {
        return aliases.getOrDefault(key(name, desc), name);
    }

    private String key(String name, String desc) {
        return name + desc;
    }

    private Map<String, String> commandRenameMap() {
        Map<String, String> out = new LinkedHashMap<>();
        if (!config.bool("minecraft.commandRename.enabled", false)) return out;
        java.util.List<String> targets = config.list("minecraft.commandRename.targets");
        if (targets.isEmpty()) return out;
        String prefix = config.string("minecraft.commandRename.prefix", "k").toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9_-]", "x");
        if (prefix.isBlank()) prefix = "k";
        long seed = config.seed() == 0 ? 0x6d637368L : config.seed();
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (String raw : targets) {
            if (raw == null || raw.isBlank()) continue;
            String cmd = raw.trim().toLowerCase(java.util.Locale.ROOT);
            long x = (seed ^ cmd.hashCode() * 0x9e3779b97f4a7c15L ^ 0x243f6a8885a308d3L);
            StringBuilder name = new StringBuilder(prefix);
            int len = Math.max(8, config.integer("minecraft.commandRename.nameLength", 18));
            while (name.length() < len) {
                x ^= (x << 13); x ^= (x >>> 7); x ^= (x << 17);
                name.append(alphabet.charAt((int)Math.floorMod(x, alphabet.length())));
            }
            out.put(cmd, name.toString());
        }
        return out;
    }

    private void rewriteGetCommandLiterals(ClassNode cn) {
        Map<String, String> map = commandRenameMap();
        if (map.isEmpty()) return;
        int changed = 0;
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof MethodInsnNode mi)) continue;
                if (!"getCommand".equals(mi.name) || !"(Ljava/lang/String;)Lorg/bukkit/command/PluginCommand;".equals(mi.desc)) continue;
                AbstractInsnNode prev = previousReal(mi.getPrevious());
                if (prev instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    String repl = map.get(s.toLowerCase(java.util.Locale.ROOT));
                    if (repl != null) {
                        ldc.cst = repl;
                        changed++;
                    }
                }
            }
        }
        if (changed > 0) System.out.println("[mcshield] shellDelegate remapped getCommand literals=" + changed);
    }

    private void rewriteConstructors(ClassNode cn, String owner) {
        for (MethodNode mn : cn.methods) {
            if (!"<init>".equals(mn.name)) continue;
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode mi && mi.getOpcode() == INVOKESPECIAL && JAVA_PLUGIN.equals(mi.owner) && "<init>".equals(mi.name) && "()V".equals(mi.desc)) {
                    mi.owner = "java/lang/Object";
                }
            }
        }
    }

    private void rewriteJavaPluginCalls(ClassNode cn, String owner, String ctxField) {
        for (MethodNode mn : cn.methods) {
            if ("<init>".equals(mn.name)) continue;
            InsnList list = mn.instructions;
            for (AbstractInsnNode insn = list.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode mi) {
                    if (mi.getOpcode() == INVOKEVIRTUAL && JAVA_PLUGIN.equals(mi.owner)) {
                        // Calls like this.getCommand()/this.getLogger() now resolve to delegate helper methods.
                        mi.owner = owner;
                    }
                    if ((mi.getOpcode() == INVOKEVIRTUAL || mi.getOpcode() == INVOKEINTERFACE || mi.getOpcode() == INVOKESPECIAL)
                            && (mi.desc.contains("Lorg/bukkit/plugin/Plugin;") || mi.desc.contains("Lorg/bukkit/plugin/java/JavaPlugin;"))) {
                        rewriteImmediateThisPluginArg(list, mi, owner, ctxField);
                    }
                }
            }
        }
    }

    private void rewriteImmediateThisPluginArg(InsnList list, MethodInsnNode call, String owner, String ctxField) {
        Type[] args = Type.getArgumentTypes(call.desc);
        if (args.length == 0) return;
        Type last = args[args.length - 1];
        String cn = last.getSort() == Type.OBJECT ? last.getInternalName() : "";
        if (!"org/bukkit/plugin/Plugin".equals(cn) && !JAVA_PLUGIN.equals(cn)) return;
        AbstractInsnNode prev = previousReal(call.getPrevious());
        if (prev instanceof VarInsnNode vn && vn.getOpcode() == ALOAD && vn.var == 0) {
            InsnList repl = new InsnList();
            repl.add(new VarInsnNode(ALOAD, 0));
            repl.add(new FieldInsnNode(GETFIELD, owner, ctxField, "L" + JAVA_PLUGIN + ";"));
            list.insert(prev, repl);
            list.remove(prev);
        }
    }

    private AbstractInsnNode previousReal(AbstractInsnNode n) {
        while (n != null && (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode)) n = n.getPrevious();
        return n;
    }

    private void addBind(ClassNode cn, String ctxField, String bindMethod) {
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, bindMethod, "(L" + JAVA_PLUGIN + ";)V", null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new FieldInsnNode(PUTFIELD, cn.name, ctxField, "L" + JAVA_PLUGIN + ";"));
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private void addContextHelpers(ClassNode cn, String ctxField) {
        // Add common JavaPlugin methods used by plugins. Existing methods win.
        helper(cn, ctxField, "getCommand", "(Ljava/lang/String;)Lorg/bukkit/command/PluginCommand;", ALOAD, 1);
        helper(cn, ctxField, "getServer", "()Lorg/bukkit/Server;");
        helper(cn, ctxField, "getLogger", "()Ljava/util/logging/Logger;");
        helper(cn, ctxField, "getName", "()Ljava/lang/String;");
        helper(cn, ctxField, "getDataFolder", "()Ljava/io/File;");
        helper(cn, ctxField, "getDescription", "()Lorg/bukkit/plugin/PluginDescriptionFile;");
        helper(cn, ctxField, "getConfig", "()Lorg/bukkit/configuration/file/FileConfiguration;");
        helper(cn, ctxField, "isEnabled", "()Z");
        helper(cn, ctxField, "reloadConfig", "()V");
        helper(cn, ctxField, "saveConfig", "()V");
        helper(cn, ctxField, "saveDefaultConfig", "()V");
        helper(cn, ctxField, "getResource", "(Ljava/lang/String;)Ljava/io/InputStream;", ALOAD, 1);
        helper(cn, ctxField, "saveResource", "(Ljava/lang/String;Z)V", ALOAD, 1, ILOAD, 2);
    }

    private void helper(ClassNode cn, String ctxField, String name, String desc, int... loads) {
        if (find(cn, name, desc) != null) return;
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, desc, null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new FieldInsnNode(GETFIELD, cn.name, ctxField, "L" + JAVA_PLUGIN + ";"));
        for (int i = 0; i < loads.length; i += 2) mn.instructions.add(new VarInsnNode(loads[i], loads[i + 1]));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, JAVA_PLUGIN, name, desc, false));
        Type ret = Type.getReturnType(desc);
        mn.instructions.add(new InsnNode(ret.getOpcode(IRETURN)));
        cn.methods.add(mn);
    }

    private byte[] generateShell(String owner, String delegate, String runtimeDelegate, String delegateField, String ensureMethod, String bindMethod, String decoderMethod, String invokerMethod, ClassNode delegateNode, Map<String, String> bridgeAliases, List<CommandSpec> virtualCommands, List<PermissionSpec> virtualPermissions) {
        ClassNode cn = new ClassNode(ASM9);
        cn.version = V1_8;
        cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
        cn.name = owner;
        cn.superName = JAVA_PLUGIN;
        cn.sourceFile = config.string("shellDelegate.sourceFile", "pivot.c");
        boolean opaque = config.bool("shellDelegate.hideDelegateDescriptor", true);
        cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_TRANSIENT | ACC_SYNTHETIC, delegateField, opaque ? "Ljava/lang/Object;" : "L" + delegate + ";", null, null));
        addCtor(cn);
        if (opaque) {
            addDecoder(cn, decoderMethod);
            addInvoker(cn, invokerMethod);
            addEnsureOpaque(cn, owner, runtimeDelegate, delegateField, ensureMethod, bindMethod, decoderMethod);
            addLifecycleOpaque(cn, owner, delegateField, ensureMethod, invokerMethod, decoderMethod, delegateNode, bridgeAliases);
            addCommandOpaque(cn, owner, delegateField, ensureMethod, invokerMethod, decoderMethod, delegateNode, bridgeAliases);
            addTabOpaque(cn, owner, delegateField, ensureMethod, invokerMethod, decoderMethod, delegateNode, bridgeAliases);
        } else {
            addEnsure(cn, owner, delegate, delegateField, ensureMethod, bindMethod);
            addLifecycle(cn, owner, delegate, delegateField, ensureMethod, delegateNode);
            addCommand(cn, owner, delegate, delegateField, ensureMethod, delegateNode);
            addTab(cn, owner, delegate, delegateField, ensureMethod, delegateNode);
        }
        if (config.bool("minecraft.virtualPermissions.enabled", false) && virtualPermissions != null && !virtualPermissions.isEmpty()) {
            String permMethod = bridgeName("p", owner + ":perm:" + config.seed(), 18);
            addVirtualPermissionRegistrar(cn, owner, permMethod, decoderMethod, virtualPermissions);
            injectCommandRegistrar(cn, owner, permMethod);
        }
        if (config.bool("minecraft.virtualCommands.enabled", false) && virtualCommands != null && !virtualCommands.isEmpty()) {
            String regMethod = bridgeName("c", owner + ":cmd:" + config.seed(), 18);
            addVirtualCommandRegistrar(cn, owner, regMethod, decoderMethod, virtualCommands);
            injectCommandRegistrar(cn, owner, regMethod);
        }
        addShellNoise(cn, owner);
        patchShellOwner(cn, owner);
        JarIO.SafeClassWriter cw = new JarIO.SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }


    private record CommandSpec(String name, List<String> aliases, String description, String usage, String permission, String permissionMessage) {}
    private record PermissionSpec(String name, String def) {}

    private List<PermissionSpec> collectVirtualPermissions(JarModel model) {
        if (!config.bool("minecraft.virtualPermissions.enabled", false)) return java.util.Collections.emptyList();
        List<String> targets = config.list("minecraft.virtualPermissions.targets");
        List<PermissionSpec> out = new ArrayList<>();
        if (!targets.isEmpty()) {
            for (String raw : targets) {
                if (raw == null || raw.isBlank()) continue;
                String name = raw.trim();
                String def = config.string("minecraft.virtualPermissions.default." + name, "false");
                out.add(new PermissionSpec(name, def));
            }
        } else {
            byte[] plugin = model.resources.get("plugin.yml");
            if (plugin == null) plugin = model.resources.get("paper-plugin.yml");
            out.addAll(parsePermissionSpecs(plugin == null ? "" : new String(plugin, StandardCharsets.UTF_8)));
        }
        if (!out.isEmpty()) System.out.println("[mcshield] shellDelegate virtualPermissions captured " + out.size() + " runtime permissions");
        return out;
    }

    private List<PermissionSpec> parsePermissionSpecs(String text) {
        List<PermissionSpec> out = new ArrayList<>();
        if (text == null || text.isBlank()) return out;
        Pattern header = Pattern.compile("(?m)^(\\s*)permissions\\s*:\\s*(?:#.*)?$");
        Matcher hm = header.matcher(text);
        if (!hm.find()) return out;
        int rootIndent = hm.group(1).length();
        int blockStart = hm.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= rootIndent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String[] lines = text.substring(blockStart, blockEnd).split("\\n", -1);
        Pattern keyPat = Pattern.compile("^(\\s{0," + (rootIndent + 8) + "})([A-Za-z0-9_.-]+)\\s*:\\s*(?:#.*)?$");
        String current = null;
        String def = "false";
        for (String line : lines) {
            int ind = 0;
            while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
            Matcher km = keyPat.matcher(line);
            if (ind == rootIndent + 2 && km.find()) {
                if (current != null) out.add(new PermissionSpec(current, def));
                current = km.group(2);
                def = "false";
                continue;
            }
            if (current == null) continue;
            String t = line.trim();
            if (t.startsWith("default:")) def = unquoteYaml(t.substring("default:".length()).trim());
        }
        if (current != null) out.add(new PermissionSpec(current, def));
        return out;
    }

    private List<CommandSpec> collectVirtualCommands(JarModel model) {
        if (!config.bool("minecraft.virtualCommands.enabled", false)) return java.util.Collections.emptyList();
        List<String> targets = config.list("minecraft.virtualCommands.targets");
        byte[] plugin = model.resources.get("plugin.yml");
        if (plugin == null) plugin = model.resources.get("paper-plugin.yml");
        java.util.Map<String, CommandSpec> parsed = parseCommandSpecs(plugin == null ? "" : new String(plugin, StandardCharsets.UTF_8));
        List<CommandSpec> out = new ArrayList<>();
        if (!targets.isEmpty()) {
            for (String raw : targets) {
                if (raw == null || raw.isBlank()) continue;
                String name = raw.trim().toLowerCase(java.util.Locale.ROOT);
                CommandSpec base = parsed.get(name);
                List<String> aliases = new ArrayList<>();
                if (base != null) aliases.addAll(base.aliases());
                aliases.addAll(config.list("minecraft.virtualCommands.aliases." + name));
                aliases = dedupeAliases(aliases, name);
                String desc = config.string("minecraft.virtualCommands.description." + name, base == null ? "" : base.description());
                String usage = config.string("minecraft.virtualCommands.usage." + name, base == null ? "/<command>" : base.usage());
                String perm = config.string("minecraft.virtualCommands.permission." + name, base == null ? "" : base.permission());
                String permMsg = config.string("minecraft.virtualCommands.permissionMessage." + name, base == null ? "" : base.permissionMessage());
                out.add(new CommandSpec(name, aliases, desc, usage, perm, permMsg));
            }
        } else {
            out.addAll(parsed.values());
        }
        if (!out.isEmpty()) System.out.println("[mcshield] shellDelegate virtualCommands captured " + out.size() + " runtime commands");
        return out;
    }

    private List<String> dedupeAliases(List<String> aliases, String name) {
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>();
        for (String a : aliases) {
            if (a == null) continue;
            String x = a.trim().toLowerCase(java.util.Locale.ROOT);
            if (x.isBlank() || x.equals(name)) continue;
            if (x.matches("[a-z0-9_-]{1,64}")) set.add(x);
        }
        return new ArrayList<>(set);
    }

    private java.util.Map<String, CommandSpec> parseCommandSpecs(String text) {
        java.util.Map<String, CommandSpec> out = new java.util.LinkedHashMap<>();
        if (text == null || text.isBlank()) return out;
        Pattern header = Pattern.compile("(?m)^(\\s*)commands\\s*:\\s*(?:#.*)?$");
        Matcher hm = header.matcher(text);
        if (!hm.find()) return out;
        int cmdIndent = hm.group(1).length();
        int blockStart = hm.end();
        if (blockStart < text.length() && text.charAt(blockStart) == '\n') blockStart++;
        int blockEnd = text.length();
        int pos = blockStart;
        while (pos < text.length()) {
            int next = text.indexOf('\n', pos);
            if (next < 0) next = text.length();
            String line = text.substring(pos, next);
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                int ind = 0;
                while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
                if (ind <= cmdIndent) { blockEnd = pos; break; }
            }
            pos = next + 1;
        }
        String[] lines = text.substring(blockStart, blockEnd).split("\\n", -1);
        Pattern keyPat = Pattern.compile("^(\\s{0," + (cmdIndent + 8) + "})([A-Za-z0-9_-]+)\\s*:\\s*(?:#.*)?$");
        String current = null;
        String desc = "";
        String usage = "/<command>";
        String permission = "";
        String permissionMessage = "";
        List<String> aliases = new ArrayList<>();
        java.util.function.Consumer<String> flush = (ignored) -> {
            // placeholder; actual flush is inline below to keep Java 17 happy with effectively-final vars
        };
        for (String line : lines) {
            int ind = 0;
            while (ind < line.length() && Character.isWhitespace(line.charAt(ind))) ind++;
            Matcher km = keyPat.matcher(line);
            if (ind == cmdIndent + 2 && km.find()) {
                if (current != null) out.put(current, new CommandSpec(current, dedupeAliases(aliases, current), desc, usage, permission, permissionMessage));
                current = km.group(2).toLowerCase(java.util.Locale.ROOT);
                desc = "";
                usage = "/<command>";
                permission = "";
                permissionMessage = "";
                aliases = new ArrayList<>();
                continue;
            }
            if (current == null) continue;
            String t = line.trim();
            if (t.startsWith("description:")) desc = unquoteYaml(t.substring("description:".length()).trim());
            else if (t.startsWith("usage:")) usage = unquoteYaml(t.substring("usage:".length()).trim());
            else if (t.startsWith("permission:")) permission = unquoteYaml(t.substring("permission:".length()).trim());
            else if (t.startsWith("permission-message:")) permissionMessage = unquoteYaml(t.substring("permission-message:".length()).trim());
            else if (t.startsWith("aliases:")) aliases.addAll(parseInlineAliases(t.substring("aliases:".length()).trim()));
        }
        if (current != null) out.put(current, new CommandSpec(current, dedupeAliases(aliases, current), desc, usage, permission, permissionMessage));
        return out;
    }

    private String unquoteYaml(String v) {
        if (v == null) return "";
        String x = v.trim();
        int hash = x.indexOf('#');
        if (hash >= 0) x = x.substring(0, hash).trim();
        if ((x.startsWith("\"") && x.endsWith("\"")) || (x.startsWith("'") && x.endsWith("'"))) x = x.substring(1, x.length() - 1);
        return x;
    }

    private List<String> parseInlineAliases(String val) {
        List<String> out = new ArrayList<>();
        if (val == null) return out;
        String x = val.trim();
        if (x.startsWith("[") && x.endsWith("]")) x = x.substring(1, x.length() - 1);
        for (String part : x.split(",")) {
            String a = unquoteYaml(part).trim();
            if (!a.isBlank()) out.add(a);
        }
        return out;
    }


    private void addVirtualPermissionRegistrar(ClassNode cn, String owner, String regMethod, String decoderMethod, List<PermissionSpec> permissions) {
        MethodNode mn = new MethodNode(ACC_PRIVATE | ACC_SYNTHETIC, regMethod, "()V", null, new String[]{"java/lang/Throwable"});
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        mn.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/Throwable"));
        mn.instructions.add(start);
        for (PermissionSpec p : permissions) {
            // try { getServer().getPluginManager().addPermission(new Permission(name, PermissionDefault.X)); } catch(Throwable ignored){}
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, owner, "getServer", "()Lorg/bukkit/Server;", false));
            mn.instructions.add(new MethodInsnNode(INVOKEINTERFACE, "org/bukkit/Server", "getPluginManager", "()Lorg/bukkit/plugin/PluginManager;", true));
            mn.instructions.add(new TypeInsnNode(NEW, "org/bukkit/permissions/Permission"));
            mn.instructions.add(new InsnNode(DUP));
            mn.instructions.add(enc(p.name(), decoderMethod));
            mn.instructions.add(new FieldInsnNode(GETSTATIC, "org/bukkit/permissions/PermissionDefault", permissionDefaultField(p.def()), "Lorg/bukkit/permissions/PermissionDefault;"));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, "org/bukkit/permissions/Permission", "<init>", "(Ljava/lang/String;Lorg/bukkit/permissions/PermissionDefault;)V", false));
            mn.instructions.add(new MethodInsnNode(INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "addPermission", "(Lorg/bukkit/permissions/Permission;)V", true));
        }
        mn.instructions.add(end);
        mn.instructions.add(new InsnNode(RETURN));
        mn.instructions.add(handler);
        mn.instructions.add(new InsnNode(POP));
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private String permissionDefaultField(String def) {
        if (def == null) return "FALSE";
        String d = def.trim().toLowerCase(java.util.Locale.ROOT);
        if (d.equals("true")) return "TRUE";
        if (d.equals("op")) return "OP";
        if (d.equals("not_op") || d.equals("notop") || d.equals("not-op")) return "NOT_OP";
        return "FALSE";
    }


    private void addVirtualCommandRegistrar(ClassNode cn, String owner, String regMethod, String decoderMethod, List<CommandSpec> commands) {
        MethodNode mn = new MethodNode(ACC_PRIVATE | ACC_SYNTHETIC, regMethod, "()V", null, new String[]{"java/lang/Throwable"});
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        mn.tryCatchBlocks.add(new TryCatchBlockNode(new LabelNode(), end, handler, "java/lang/Throwable"));
        LabelNode start = mn.tryCatchBlocks.get(0).start;
        mn.instructions.add(start);

        // Constructor<PluginCommand> ctor = PluginCommand.class.getDeclaredConstructor(String.class, Plugin.class); ctor.setAccessible(true)
        mn.instructions.add(new LdcInsnNode(Type.getType("Lorg/bukkit/command/PluginCommand;")));
        mn.instructions.add(new InsnNode(ICONST_2));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_0)); mn.instructions.add(new LdcInsnNode(Type.getType("Ljava/lang/String;"))); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_1)); mn.instructions.add(new LdcInsnNode(Type.getType("Lorg/bukkit/plugin/Plugin;"))); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getDeclaredConstructor", "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
        mn.instructions.add(new VarInsnNode(ASTORE, 1));
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Constructor", "setAccessible", "(Z)V", false));

        // Object commandMap = getServer().getClass().getMethod("getCommandMap").invoke(getServer())
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, owner, "getServer", "()Lorg/bukkit/Server;", false));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false));
        mn.instructions.add(enc("getCommandMap", decoderMethod));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, owner, "getServer", "()Lorg/bukkit/Server;", false));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        mn.instructions.add(new VarInsnNode(ASTORE, 2));

        // Method register = commandMap.getClass().getMethod("register", String.class, Command.class)
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false));
        mn.instructions.add(enc("register", decoderMethod));
        mn.instructions.add(new InsnNode(ICONST_2));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_0)); mn.instructions.add(new LdcInsnNode(Type.getType("Ljava/lang/String;"))); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_1)); mn.instructions.add(new LdcInsnNode(Type.getType("Lorg/bukkit/command/Command;"))); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        mn.instructions.add(new VarInsnNode(ASTORE, 3));

        for (CommandSpec c : commands) {
            emitRegisterOne(mn, owner, decoderMethod, c);
        }

        mn.instructions.add(end);
        mn.instructions.add(new InsnNode(RETURN));
        mn.instructions.add(handler);
        mn.instructions.add(new InsnNode(POP));
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private void emitRegisterOne(MethodNode mn, String owner, String decoderMethod, CommandSpec c) {
        // PluginCommand cmd = (PluginCommand) ctor.newInstance(name, this)
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new InsnNode(ICONST_2));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_0)); mn.instructions.add(enc(c.name(), decoderMethod)); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_1)); mn.instructions.add(new VarInsnNode(ALOAD, 0)); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;", false));
        mn.instructions.add(new TypeInsnNode(CHECKCAST, "org/bukkit/command/PluginCommand"));
        mn.instructions.add(new VarInsnNode(ASTORE, 4));
        if (c.description() != null && !c.description().isBlank() && config.bool("minecraft.virtualCommands.keepDescriptions", false)) {
            mn.instructions.add(new VarInsnNode(ALOAD, 4));
            mn.instructions.add(enc(c.description(), decoderMethod));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "org/bukkit/command/PluginCommand", "setDescription", "(Ljava/lang/String;)V", false));
        }
        mn.instructions.add(new VarInsnNode(ALOAD, 4));
        String usage = c.usage() == null || c.usage().isBlank() ? "/" + c.name() : c.usage();
        mn.instructions.add(enc(usage, decoderMethod));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "org/bukkit/command/PluginCommand", "setUsage", "(Ljava/lang/String;)V", false));
        if (c.permission() != null && !c.permission().isBlank()) {
            mn.instructions.add(new VarInsnNode(ALOAD, 4));
            mn.instructions.add(enc(c.permission(), decoderMethod));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "org/bukkit/command/PluginCommand", "setPermission", "(Ljava/lang/String;)V", false));
        }
        if (c.permissionMessage() != null && !c.permissionMessage().isBlank()) {
            mn.instructions.add(new VarInsnNode(ALOAD, 4));
            mn.instructions.add(enc(c.permissionMessage(), decoderMethod));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "org/bukkit/command/PluginCommand", "setPermissionMessage", "(Ljava/lang/String;)V", false));
        }
        if (!c.aliases().isEmpty()) {
            mn.instructions.add(new VarInsnNode(ALOAD, 4));
            mn.instructions.add(new TypeInsnNode(NEW, "java/util/ArrayList"));
            mn.instructions.add(new InsnNode(DUP));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/util/ArrayList", "<init>", "()V", false));
            for (String a : c.aliases()) {
                mn.instructions.add(new InsnNode(DUP));
                mn.instructions.add(enc(a, decoderMethod));
                mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/util/ArrayList", "add", "(Ljava/lang/Object;)Z", false));
                mn.instructions.add(new InsnNode(POP));
            }
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "org/bukkit/command/PluginCommand", "setAliases", "(Ljava/util/List;)V", false));
        }
        // register.invoke(commandMap, getDescription().getName(), cmd)
        mn.instructions.add(new VarInsnNode(ALOAD, 3));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new InsnNode(ICONST_2));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, owner, "getDescription", "()Lorg/bukkit/plugin/PluginDescriptionFile;", false));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "org/bukkit/plugin/PluginDescriptionFile", "getName", "()Ljava/lang/String;", false));
        mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new InsnNode(DUP)); mn.instructions.add(new InsnNode(ICONST_1)); mn.instructions.add(new VarInsnNode(ALOAD, 4)); mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        mn.instructions.add(new InsnNode(POP));
    }

    private void injectCommandRegistrar(ClassNode cn, String owner, String regMethod) {
        MethodNode onEnable = find(cn, "onEnable", "()V");
        if (onEnable == null || onEnable.instructions == null) return;
        InsnList ins = new InsnList();
        ins.add(new VarInsnNode(ALOAD, 0));
        ins.add(new MethodInsnNode(INVOKESPECIAL, owner, regMethod, "()V", false));
        onEnable.instructions.insert(ins);
    }


    private void patchShellOwner(ClassNode cn, String owner) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode mi && "PLACEHOLDER_OWNER".equals(mi.owner)) mi.owner = owner;
            }
        }
    }

    private void addDecoder(ClassNode cn, String decoderMethod) {
        if (find(cn, decoderMethod, "([II)Ljava/lang/String;") != null) return;
        MethodNode mn = new MethodNode(ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC, decoderMethod, "([II)Ljava/lang/String;", null, null);
        LabelNode loop = new LabelNode();
        LabelNode done = new LabelNode();
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new InsnNode(ARRAYLENGTH));
        mn.instructions.add(new IntInsnNode(NEWARRAY, T_CHAR));
        mn.instructions.add(new VarInsnNode(ASTORE, 2));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new VarInsnNode(ISTORE, 3));
        mn.instructions.add(loop);
        mn.instructions.add(new VarInsnNode(ILOAD, 3));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new InsnNode(ARRAYLENGTH));
        mn.instructions.add(new JumpInsnNode(IF_ICMPGE, done));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new VarInsnNode(ILOAD, 3));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new VarInsnNode(ILOAD, 3));
        mn.instructions.add(new InsnNode(IALOAD));
        mn.instructions.add(new VarInsnNode(ILOAD, 1));
        mn.instructions.add(new InsnNode(IXOR));
        mn.instructions.add(new VarInsnNode(ILOAD, 3));
        mn.instructions.add(new IntInsnNode(BIPUSH, 31));
        mn.instructions.add(new InsnNode(IMUL));
        mn.instructions.add(new InsnNode(IXOR));
        mn.instructions.add(new InsnNode(I2C));
        mn.instructions.add(new InsnNode(CASTORE));
        mn.instructions.add(new IincInsnNode(3, 1));
        mn.instructions.add(new JumpInsnNode(GOTO, loop));
        mn.instructions.add(done);
        mn.instructions.add(new TypeInsnNode(NEW, "java/lang/String"));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false));
        mn.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(mn);
    }

    private void addEnsureOpaque(ClassNode cn, String owner, String delegate, String delegateField, String ensureMethod, String bindMethod, String decoderMethod) {
        MethodNode mn = new MethodNode(ACC_PRIVATE | ACC_SYNTHETIC, ensureMethod, "()Ljava/lang/Object;", null, null);
        LabelNode have = new LabelNode();
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new FieldInsnNode(GETFIELD, owner, delegateField, "Ljava/lang/Object;"));
        mn.instructions.add(new JumpInsnNode(IFNONNULL, have));
        // Class<?> c = Class.forName(decodedDelegate, true, getClass().getClassLoader())
        mn.instructions.add(enc(delegate.replace('/', '.'), decoderMethod));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;", false));
        mn.instructions.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false));
        mn.instructions.add(new VarInsnNode(ASTORE, 1));
        // Object d = c.getDeclaredConstructor().newInstance()
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getDeclaredConstructor", "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;", false));
        mn.instructions.add(new VarInsnNode(ASTORE, 2));
        // bind shell context reflectively
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(enc(bindMethod, decoderMethod));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new LdcInsnNode(Type.getType("L" + JAVA_PLUGIN + ";")));
        mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "setAccessible", "(Z)V", false));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new InsnNode(ICONST_0));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new InsnNode(AASTORE));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        mn.instructions.add(new InsnNode(POP));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new FieldInsnNode(PUTFIELD, owner, delegateField, "Ljava/lang/Object;"));
        mn.instructions.add(have);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new FieldInsnNode(GETFIELD, owner, delegateField, "Ljava/lang/Object;"));
        mn.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(mn);
    }

    private void addLifecycleOpaque(ClassNode cn, String owner, String delegateField, String ensureMethod, String invokerMethod, String decoderMethod, ClassNode delegateNode, Map<String, String> aliases) {
        bridgeVoidOpaque(cn, owner, ensureMethod, invokerMethod, decoderMethod, alias(aliases, "onLoad", "()V"), "onLoad", find(delegateNode, alias(aliases, "onLoad", "()V"), "()V") != null);
        bridgeVoidOpaque(cn, owner, ensureMethod, invokerMethod, decoderMethod, alias(aliases, "onEnable", "()V"), "onEnable", find(delegateNode, alias(aliases, "onEnable", "()V"), "()V") != null);
        bridgeVoidOpaque(cn, owner, ensureMethod, invokerMethod, decoderMethod, alias(aliases, "onDisable", "()V"), "onDisable", find(delegateNode, alias(aliases, "onDisable", "()V"), "()V") != null);
    }

    private void bridgeVoidOpaque(ClassNode cn, String owner, String ensureMethod, String invokerMethod, String decoderMethod, String delegateMethod, String publicName, boolean exists) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, publicName, "()V", null, null);
        if (exists) {
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, owner, ensureMethod, "()Ljava/lang/Object;", false));
            mn.instructions.add(enc(delegateMethod, decoderMethod));
            mn.instructions.add(new InsnNode(ICONST_0));
            mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
            mn.instructions.add(new InsnNode(ICONST_0));
            mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
            mn.instructions.add(new MethodInsnNode(INVOKESTATIC, owner, invokerMethod, "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;", false));
            mn.instructions.add(new InsnNode(POP));
        }
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private void addCommandOpaque(ClassNode cn, String owner, String delegateField, String ensureMethod, String invokerMethod, String decoderMethod, ClassNode delegateNode, Map<String, String> aliases) {
        String desc = "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z";
        String dm = alias(aliases, "onCommand", desc);
        MethodNode mn = new MethodNode(ACC_PUBLIC, "onCommand", desc, null, null);
        if (find(delegateNode, dm, desc) != null) {
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, owner, ensureMethod, "()Ljava/lang/Object;", false));
            mn.instructions.add(enc(dm, decoderMethod));
            mn.instructions.add(commandTypes());
            mn.instructions.add(new InsnNode(ICONST_4));
            mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
            for (int i = 0; i < 4; i++) {
                mn.instructions.add(new InsnNode(DUP));
                mn.instructions.add(new InsnNode(ICONST_0 + i));
                mn.instructions.add(new VarInsnNode(ALOAD, i + 1));
                mn.instructions.add(new InsnNode(AASTORE));
            }
            mn.instructions.add(new MethodInsnNode(INVOKESTATIC, owner, invokerMethod, "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;", false));
            mn.instructions.add(new TypeInsnNode(CHECKCAST, "java/lang/Boolean"));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false));
            mn.instructions.add(new InsnNode(IRETURN));
        } else {
            mn.instructions.add(new InsnNode(ICONST_0));
            mn.instructions.add(new InsnNode(IRETURN));
        }
        cn.methods.add(mn);
    }

    private void addTabOpaque(ClassNode cn, String owner, String delegateField, String ensureMethod, String invokerMethod, String decoderMethod, ClassNode delegateNode, Map<String, String> aliases) {
        String desc = "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;";
        String dm = alias(aliases, "onTabComplete", desc);
        MethodNode mn = new MethodNode(ACC_PUBLIC, "onTabComplete", desc, null, null);
        if (find(delegateNode, dm, desc) != null) {
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, owner, ensureMethod, "()Ljava/lang/Object;", false));
            mn.instructions.add(enc(dm, decoderMethod));
            mn.instructions.add(commandTypes());
            mn.instructions.add(new InsnNode(ICONST_4));
            mn.instructions.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object"));
            for (int i = 0; i < 4; i++) {
                mn.instructions.add(new InsnNode(DUP));
                mn.instructions.add(new InsnNode(ICONST_0 + i));
                mn.instructions.add(new VarInsnNode(ALOAD, i + 1));
                mn.instructions.add(new InsnNode(AASTORE));
            }
            mn.instructions.add(new MethodInsnNode(INVOKESTATIC, owner, invokerMethod, "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;", false));
            mn.instructions.add(new TypeInsnNode(CHECKCAST, "java/util/List"));
            mn.instructions.add(new InsnNode(ARETURN));
        } else {
            mn.instructions.add(new InsnNode(ACONST_NULL));
            mn.instructions.add(new InsnNode(ARETURN));
        }
        cn.methods.add(mn);
    }

    private InsnList commandTypes() {
        InsnList l = new InsnList();
        l.add(new InsnNode(ICONST_4));
        l.add(new TypeInsnNode(ANEWARRAY, "java/lang/Class"));
        l.add(new InsnNode(DUP)); l.add(new InsnNode(ICONST_0)); l.add(new LdcInsnNode(Type.getType("Lorg/bukkit/command/CommandSender;"))); l.add(new InsnNode(AASTORE));
        l.add(new InsnNode(DUP)); l.add(new InsnNode(ICONST_1)); l.add(new LdcInsnNode(Type.getType("Lorg/bukkit/command/Command;"))); l.add(new InsnNode(AASTORE));
        l.add(new InsnNode(DUP)); l.add(new InsnNode(ICONST_2)); l.add(new LdcInsnNode(Type.getType("Ljava/lang/String;"))); l.add(new InsnNode(AASTORE));
        l.add(new InsnNode(DUP)); l.add(new InsnNode(ICONST_3)); l.add(new LdcInsnNode(Type.getType("[Ljava/lang/String;"))); l.add(new InsnNode(AASTORE));
        return l;
    }

    private void addInvoker(ClassNode cn, String invokerMethod) {
        if (find(cn, invokerMethod, "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;") != null) return;
        MethodNode mn = new MethodNode(ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC, invokerMethod, "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;", null, new String[] {"java/lang/Exception"});
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false));
        mn.instructions.add(new VarInsnNode(ALOAD, 1));
        mn.instructions.add(new VarInsnNode(ALOAD, 2));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new InsnNode(ICONST_1));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "setAccessible", "(Z)V", false));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new VarInsnNode(ALOAD, 3));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        mn.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(mn);
    }

    private InsnList enc(String s, String decoderMethod) {
        int key = 0x4d5a0000 ^ s.length() ^ s.hashCode();
        InsnList l = new InsnList();
        pushInt(l, s.length());
        l.add(new IntInsnNode(NEWARRAY, T_INT));
        for (int i = 0; i < s.length(); i++) {
            l.add(new InsnNode(DUP));
            pushInt(l, i);
            pushInt(l, s.charAt(i) ^ key ^ (i * 31));
            l.add(new InsnNode(IASTORE));
        }
        pushInt(l, key);
        l.add(new MethodInsnNode(INVOKESTATIC, "PLACEHOLDER_OWNER", decoderMethod, "([II)Ljava/lang/String;", false));
        return l;
    }

    private void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }

    private void addCtor(ClassNode cn) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, JAVA_PLUGIN, "<init>", "()V", false));
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private void addEnsure(ClassNode cn, String owner, String delegate, String delegateField, String ensureMethod, String bindMethod) {
        MethodNode mn = new MethodNode(ACC_PRIVATE | ACC_SYNTHETIC, ensureMethod, "()L" + delegate + ";", null, null);
        LabelNode have = new LabelNode();
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new FieldInsnNode(GETFIELD, owner, delegateField, "L" + delegate + ";"));
        mn.instructions.add(new JumpInsnNode(IFNONNULL, have));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new TypeInsnNode(NEW, delegate));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, delegate, "<init>", "()V", false));
        mn.instructions.add(new InsnNode(DUP));
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, delegate, bindMethod, "(L" + JAVA_PLUGIN + ";)V", false));
        mn.instructions.add(new FieldInsnNode(PUTFIELD, owner, delegateField, "L" + delegate + ";"));
        mn.instructions.add(have);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new FieldInsnNode(GETFIELD, owner, delegateField, "L" + delegate + ";"));
        mn.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(mn);
    }

    private void addLifecycle(ClassNode cn, String owner, String delegate, String delegateField, String ensureMethod, ClassNode delegateNode) {
        bridgeVoid(cn, owner, delegate, ensureMethod, "onLoad", "()V", find(delegateNode, "onLoad", "()V") != null);
        bridgeVoid(cn, owner, delegate, ensureMethod, "onEnable", "()V", find(delegateNode, "onEnable", "()V") != null);
        bridgeVoid(cn, owner, delegate, ensureMethod, "onDisable", "()V", find(delegateNode, "onDisable", "()V") != null);
    }

    private void bridgeVoid(ClassNode cn, String owner, String delegate, String ensureMethod, String name, String desc, boolean exists) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, name, desc, null, null);
        if (exists) {
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, owner, ensureMethod, "()L" + delegate + ";", false));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, delegate, name, desc, false));
        }
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private void addCommand(ClassNode cn, String owner, String delegate, String delegateField, String ensureMethod, ClassNode delegateNode) {
        String desc = "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z";
        MethodNode mn = new MethodNode(ACC_PUBLIC, "onCommand", desc, null, null);
        if (find(delegateNode, "onCommand", desc) != null) {
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, owner, ensureMethod, "()L" + delegate + ";", false));
            mn.instructions.add(new VarInsnNode(ALOAD, 1));
            mn.instructions.add(new VarInsnNode(ALOAD, 2));
            mn.instructions.add(new VarInsnNode(ALOAD, 3));
            mn.instructions.add(new VarInsnNode(ALOAD, 4));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, delegate, "onCommand", desc, false));
            mn.instructions.add(new InsnNode(IRETURN));
        } else {
            mn.instructions.add(new InsnNode(ICONST_0));
            mn.instructions.add(new InsnNode(IRETURN));
        }
        cn.methods.add(mn);
    }

    private void addTab(ClassNode cn, String owner, String delegate, String delegateField, String ensureMethod, ClassNode delegateNode) {
        String desc = "(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;";
        MethodNode mn = new MethodNode(ACC_PUBLIC, "onTabComplete", desc, null, null);
        if (find(delegateNode, "onTabComplete", desc) != null) {
            mn.instructions.add(new VarInsnNode(ALOAD, 0));
            mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, owner, ensureMethod, "()L" + delegate + ";", false));
            mn.instructions.add(new VarInsnNode(ALOAD, 1));
            mn.instructions.add(new VarInsnNode(ALOAD, 2));
            mn.instructions.add(new VarInsnNode(ALOAD, 3));
            mn.instructions.add(new VarInsnNode(ALOAD, 4));
            mn.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, delegate, "onTabComplete", desc, false));
            mn.instructions.add(new InsnNode(ARETURN));
        } else {
            mn.instructions.add(new InsnNode(ACONST_NULL));
            mn.instructions.add(new InsnNode(ARETURN));
        }
        cn.methods.add(mn);
    }

    private void addShellNoise(ClassNode cn, String owner) {
        int fields = Math.max(0, config.integer("shellDelegate.noiseFields", 24));
        int methods = Math.max(0, config.integer("shellDelegate.noiseMethods", 64));
        for (int i = 0; i < fields; i++) cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_SYNTHETIC, "m" + Integer.toHexString(owner.hashCode() ^ (i * 0x45d9f3b)), i % 3 == 0 ? "Ljava/util/Map;" : (i % 3 == 1 ? "Ljava/lang/Object;" : "I"), null, null));
        String[] names = config.bool("shellDelegate.noiseSensitiveNames", false)
                ? new String[] {"reloadPlugin", "checkLicense", "createHttpClient", "processSuccessPayment", "processManualTopup", "handleCardResponse", "giveCardReward", "getPendingCards"}
                : new String[0];
        for (int i = 0; i < methods; i++) {
            String n = i < names.length ? names[i] : "x" + Integer.toHexString(owner.hashCode() + i * 31);
            MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, n, i % 2 == 0 ? "()V" : "()Ljava/lang/Object;", null, null);
            mn.instructions.add(new LdcInsnNode(owner.hashCode() ^ i));
            mn.instructions.add(new InsnNode(POP));
            if (i % 2 == 0) mn.instructions.add(new InsnNode(RETURN));
            else { mn.instructions.add(new InsnNode(ACONST_NULL)); mn.instructions.add(new InsnNode(ARETURN)); }
            cn.methods.add(mn);
        }
    }

    private MethodNode find(ClassNode cn, String name, String desc) {
        for (MethodNode mn : cn.methods) if (mn.name.equals(name) && mn.desc.equals(desc)) return mn;
        return null;
    }

    private String unique(String base, JarModel model, Map<String, byte[]> generatedClasses) {
        String stem = base;
        int i = 0;
        while (model.classes.containsKey(stem) || generatedClasses.containsKey(stem)) stem = base + (++i);
        return stem;
    }


    private Map<String, byte[]> generateDelegateDecoys(JarModel model, Map<String, byte[]> generatedClasses, String realOwner, String runtimeOwner, ClassNode realNode, String ctxField, String bindMethod) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.bool("shellDelegate.delegateDecoys.enabled", true)) return out;
        int count = Math.max(0, config.integer("shellDelegate.delegateDecoys.classes", 120));
        if (count == 0) return out;
        int fields = Math.max(0, config.integer("shellDelegate.delegateDecoys.fieldCount", Math.max(24, realNode.fields.size() + 12)));
        int methods = Math.max(0, config.integer("shellDelegate.delegateDecoys.methodCount", Math.max(96, realNode.methods.size() + 48)));
        String pkg = config.string("shellDelegate.delegateDecoys.package", "");
        if (pkg == null || pkg.isBlank()) {
            boolean sameRuntimePackage = config.bool("shellDelegate.delegateDecoys.sameRuntimePackage", true);
            pkg = sameRuntimePackage ? packageOf(runtimeOwner) : packageOf(realOwner);
        }
        if (pkg == null || pkg.isBlank()) pkg = "z";
        pkg = owner(pkg);
        int seed = (realOwner + ":delegate-decoys").hashCode();
        for (int i = 0; i < count; i++) {
            String name = unique(pkg + "/" + decoyName(seed, i, 48 + (i % 23)), model, generatedClasses);
            ClassNode cn = new ClassNode(ASM9);
            cn.version = V1_8;
            cn.access = ACC_PUBLIC | ACC_SUPER | ACC_SYNTHETIC;
            cn.name = name;
            cn.superName = "java/lang/Object";
            cn.sourceFile = config.string("shellDelegate.delegateDecoys.sourceFile", "entry.c");
            addPlainObjectCtor(cn);
            int localFields = mixedDecoyFieldCount(fields, i);
            int localMethods = mixedDecoyMethodCount(methods, i);
            addDelegateDecoyFields(cn, name, localFields, ctxField);
            addDelegateDecoyMethods(cn, name, localMethods, ctxField, bindMethod);
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            cn.accept(cw);
            out.put(name, cw.toByteArray());
        }
        return out;
    }

    private String packageOf(String owner) {
        int idx = owner.lastIndexOf('/');
        return idx < 0 ? "z" : owner.substring(0, idx);
    }

    private String decoyName(int seed, int idx, int len) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder();
        long x = (seed * 1103515245L + idx * 0x9e3779b97f4a7c15L) ^ 0x5deece66dL;
        for (int i = 0; i < len; i++) {
            x ^= (x << 13);
            x ^= (x >>> 7);
            x ^= (x << 17);
            int v = (int)Math.floorMod(x + i * 31L, alphabet.length());
            sb.append(alphabet.charAt(v));
        }
        return sb.toString();
    }

    private void addPlainObjectCtor(ClassNode cn) {
        MethodNode mn = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        mn.instructions.add(new VarInsnNode(ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        mn.instructions.add(new InsnNode(RETURN));
        cn.methods.add(mn);
    }

    private void addDelegateDecoyFields(ClassNode cn, String owner, int count, String ctxField) {
        String[] names = {"licenseManager", "pendingCards", "bankPaymentManager", "paymentGuiManager", "milestoneManager", "cardManager", "storage", "pending", "paymentCache", "httpClient", "api", "scheduler", "logger", "plugin", "provider", "gateway", "webhook", "service"};
        String[] descs = {"Ljava/lang/Object;", "Ljava/util/Map;", "Ljava/util/List;", "Ljava/lang/String;", "I", "Z", "J"};
        if (config.bool("shellDelegate.delegateDecoys.mirrorBridgeNames", true)) {
            cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_TRANSIENT | ACC_SYNTHETIC, uniqueFieldName(cn, ctxField), "L" + JAVA_PLUGIN + ";", null, null));
        }
        if (config.bool("shellDelegate.delegateDecoys.contextStringFields", true)) {
            java.util.List<String> ctx = delegateContextStrings();
            for (int i = 0; i < ctx.size(); i++) {
                String n = uniqueFieldName(cn, "s" + Integer.toHexString((owner + ctx.get(i) + i).hashCode()).replace('-', 'n'));
                cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_STATIC | ACC_FINAL | ACC_SYNTHETIC, n, "Ljava/lang/String;", null, ctx.get(i)));
            }
        }
        for (int i = 0; i < count; i++) {
            String base = i < names.length ? names[i] : "f" + Integer.toHexString(owner.hashCode() ^ i * 0x45d9f3b);
            String name = uniqueFieldName(cn, base);
            cn.fields.add(new FieldNode(ACC_PRIVATE | ACC_SYNTHETIC, name, descs[Math.floorMod(owner.hashCode() + i, descs.length)], null, null));
        }
    }

    private java.util.List<String> delegateContextStrings() {
        java.util.List<String> fromConfig = config.list("shellDelegate.delegateDecoys.contextStrings");
        if (!fromConfig.isEmpty()) return fromConfig;
        return java.util.List.of(
                "Discord", "webhook", "discord-webhook.url", "discord-webhook.enabled",
                "Discord card webhook failed", "minotar", "manual topup", "promotionPath",
                "reward-command", "card.webhook-title", "card.success-broadcast", "card.webhook-footer",
                "bank", "napthe", "korapayments", "kora-admin", "topnap", "lichsunap",
                "mocnap", "confirmcard", "cancelcard", "general.currency", "promotion.bonus-channel",
                "webhook.field-player", "webhook.field-card", "webhook.field-amount", "webhook.field-time"
        );
    }

    private String uniqueFieldName(ClassNode cn, String base) {
        String n = base;
        int i = 0;
        while (hasField(cn, n)) n = base + Integer.toHexString(++i);
        return n;
    }

    private boolean hasField(ClassNode cn, String name) {
        for (FieldNode fn : cn.fields) if (fn.name.equals(name)) return true;
        return false;
    }

    private void addDelegateDecoyMethods(ClassNode cn, String owner, int count, String ctxField, String bindMethod) {
        // Mirror the real delegate surface better. Earlier decoys had
        // payment/check methods but missed the manager/API getter cluster, so a simple scan for
        // getDatabaseManager/getBankPaymentManager/getPendingCards still isolated the delegate.
        // These are harmless generated methods, but they make name-bundle scans noisy.
        String[][] prime = delegateSurfaceMethods();
        int added = 0;
        if (config.bool("shellDelegate.delegateDecoys.mirrorBridgeNames", true)) {
            addDecoyMethod(cn, bindMethod, "(L" + JAVA_PLUGIN + ";)V", owner.hashCode() ^ 0x5eed);
            added++;
            for (String[] w : bridgeWrapperSurface()) {
                addDecoyMethod(cn, w[0], w[1], owner.hashCode() ^ added);
                added++;
            }
        }
        int repeat = Math.max(1, config.integer("shellDelegate.delegateDecoys.surfaceRepeats", 2));
        for (int r = 0; r < repeat; r++) {
            for (String[] m : prime) {
                String name = r == 0 ? m[0] : m[0] + Integer.toHexString((owner + r + m[0]).hashCode()).replace('-', 'n');
                addDecoyMethod(cn, name, m[1], owner.hashCode() ^ added);
                added++;
            }
        }
        for (int i = added; i < count; i++) {
            String base = "m" + Integer.toHexString(owner.hashCode() ^ i * 0x7f4a7c15);
            String desc;
            switch (Math.floorMod(owner.hashCode() + i, 6)) {
                case 0 -> desc = "()V";
                case 1 -> desc = "()Z";
                case 2 -> desc = "()Ljava/lang/Object;";
                case 3 -> desc = "(Ljava/lang/Object;)V";
                case 4 -> desc = "(Ljava/lang/String;)Ljava/lang/Object;";
                default -> desc = "()Ljava/util/Map;";
            }
            addDecoyMethod(cn, uniqueMethodName(cn, base, desc), desc, owner.hashCode() ^ i);
        }
    }

    private void addDecoyMethod(ClassNode cn, String name, String desc, int salt) {
        if (find(cn, name, desc) != null) name = uniqueMethodName(cn, name, desc);
        MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_SYNTHETIC, name, desc, null, null);
        mn.instructions.add(new LdcInsnNode(salt));
        mn.instructions.add(new InsnNode(POP));
        Type ret = Type.getReturnType(desc);
        switch (ret.getSort()) {
            case Type.VOID -> mn.instructions.add(new InsnNode(RETURN));
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> { mn.instructions.add(new InsnNode(ICONST_0)); mn.instructions.add(new InsnNode(IRETURN)); }
            case Type.LONG -> { mn.instructions.add(new InsnNode(LCONST_0)); mn.instructions.add(new InsnNode(LRETURN)); }
            case Type.FLOAT -> { mn.instructions.add(new InsnNode(FCONST_0)); mn.instructions.add(new InsnNode(FRETURN)); }
            case Type.DOUBLE -> { mn.instructions.add(new InsnNode(DCONST_0)); mn.instructions.add(new InsnNode(DRETURN)); }
            default -> { mn.instructions.add(new InsnNode(ACONST_NULL)); mn.instructions.add(new InsnNode(ARETURN)); }
        }
        cn.methods.add(mn);
    }

    private Map<String, byte[]> metadata(String publicOwner) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (!config.bool("shellDelegate.emitMetadata", true)) return out;
        out.put("META-INF/.mcshield/trampoline/" + Integer.toHexString(publicOwner.hashCode()) + ".dat", new byte[] {0x21, 0x13, 0x37, 0x42});
        if (config.bool("shellDelegate.commandDescriptorDecoys", true)) {
            String[] commands = {"bank", "napthe", "confirmcard", "cancelcard", "topnap", "lichsunap", "mocnap", "korapayments", "kora-admin"};
            for (int i = 0; i < 24; i++) {
                StringBuilder sb = new StringBuilder();
                sb.append("commands:\n");
                int salt = publicOwner.hashCode() ^ (i * 0x9e3779b9);
                for (String c : commands) {
                    sb.append("  ").append(c).append(Integer.toHexString(salt ^ c.hashCode()).substring(0, 2)).append(":\n");
                    sb.append("    description: ").append(Integer.toHexString(salt ^ (c.length() * 31))).append("\n");
                }
                out.put("META-INF/.mcshield/descriptors/" + Integer.toHexString(salt) + ".yml", sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    private String owner(String s) {
        if (s == null) return "";
        String out = s.trim().replace('.', '/');
        while (out.startsWith("/")) out = out.substring(1);
        while (out.endsWith("/")) out = out.substring(0, out.length() - 1);
        return out;
    }

    public record Result(boolean enabled, String publicOwner, String delegateOwner, Map<String, String> yamlRemap) {
        public static Result disabled() { return new Result(false, null, null, Map.of()); }
    }
}
