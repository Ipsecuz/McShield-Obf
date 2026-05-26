package dev.mcshield.obf;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.JarIO;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.modules.AntiDebug;
import dev.mcshield.obf.modules.AntiDecompile;
import dev.mcshield.obf.modules.ControlFlow;
import dev.mcshield.obf.modules.CStyleDecoy;
import dev.mcshield.obf.modules.DeadCode;
import dev.mcshield.obf.modules.DecoyTree;
import dev.mcshield.obf.modules.JavaPluginDecoys;
import dev.mcshield.obf.modules.JavaPluginUnderlay;
import dev.mcshield.obf.modules.EntryPointProxy;
import dev.mcshield.obf.modules.FieldAccessReflection;
import dev.mcshield.obf.modules.MappingContext;
import dev.mcshield.obf.modules.NativeGuard;
import dev.mcshield.obf.modules.Optimizer;
import dev.mcshield.obf.modules.ReferenceReflection;
import dev.mcshield.obf.modules.Renamer;
import dev.mcshield.obf.modules.StringEncryptor;
import dev.mcshield.obf.modules.ShadowBoot;
import dev.mcshield.obf.modules.ShadowVault;
import dev.mcshield.obf.modules.ShellDelegate;
import dev.mcshield.obf.modules.Watermark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Core {
    private Core() {}

    public static void run(String[] args) throws Exception {
        Cli cli = Cli.parse(args);
        if (cli.help) {
            printHelp();
            return;
        }
        ObfConfig config = ObfConfig.load(cli.config);
        long seed = config.seed();
        System.out.println("[mcshield] input  = " + cli.input);
        System.out.println("[mcshield] output = " + cli.output);
        System.out.println("[mcshield] seed   = " + seed);
        if (cli.lib != null) System.out.println("[mcshield] lib    = " + cli.lib + " (accepted for CLI compatibility; safe frame writer does not require classpath)");
        config.printEffectiveSummary();

        JarModel model = JarIO.read(cli.input);
        System.out.println("[mcshield] loaded classes=" + model.classes.size() + ", resources=" + model.resources.size());
        if (model.pluginMainFqn != null) System.out.println("[mcshield] plugin main = " + model.pluginMainFqn);
        else System.err.println("[mcshield] warning: plugin.yml/paper-plugin.yml main not found");

        RuntimeOwners rt = RuntimeOwners.from(config);
        MappingContext mapping = new Renamer(config, seed).build(model);
        printMainRemap(model, mapping);

        Map<String, byte[]> generatedClasses = new LinkedHashMap<>();
        Map<String, byte[]> generatedResources = new LinkedHashMap<>();

        ShellDelegate.Result shellDelegate = new ShellDelegate(config).apply(model, mapping, generatedClasses, generatedResources);
        if (shellDelegate.enabled()) {
            System.out.println("[mcshield] shellDelegate plugin.yml main -> " + shellDelegate.publicOwner().replace('/', '.')
                    + " (delegate=" + shellDelegate.delegateOwner().replace('/', '.') + ")");
        }

        JavaPluginUnderlay.Result underlay = shellDelegate.enabled()
                ? new JavaPluginUnderlay.Result(false, null, null, null, 0)
                : new JavaPluginUnderlay(config, seed).apply(model, generatedClasses);
        if (underlay.enabled()) {
            System.out.println("[mcshield] javaPluginUnderlay inserted " + underlay.chainLength()
                    + " superclass decoys below real main -> " + underlay.topUnderlay().replace('/', '.'));
        }

        EntryPointProxy.Result entryProxy = shellDelegate.enabled()
                ? new EntryPointProxy.Result(false, null, null, null, 0)
                : new EntryPointProxy(config, seed).apply(model, mapping, generatedClasses);
        if (entryProxy.enabled()) {
            System.out.println("[mcshield] entrypointProxy chain leaf -> " + entryProxy.proxyOwner().replace('/', '.') + " (chain=" + entryProxy.chainDepth() + ")");
        }

        ShadowBoot.Result shadowBoot = shellDelegate.enabled()
                ? new ShadowBoot.Result(false, null, null, null)
                : new ShadowBoot(config).apply(model, mapping, entryProxy, generatedClasses, generatedResources);
        if (shadowBoot.enabled()) {
            System.out.println("[mcshield] shadowBoot plugin.yml main -> " + shadowBoot.publicOwner().replace('/', '.') + " (extends hidden route)");
        }

        byte[] wrapper = new ReferenceReflection(config, rt.refOwner, rt.stringsOwner, rt.wrapperOwner).apply(model);
        if (wrapper != null) generatedClasses.put(rt.wrapperOwner, wrapper);

        int fieldRefs = new FieldAccessReflection(config, mapping, rt.refOwner, rt.stringsOwner).apply(model);
        if (fieldRefs > 0) System.out.println("[mcshield] fieldReflection rewrote " + fieldRefs + " field accesses");

        int guards = new AntiDebug(config, rt.guardOwner).apply(model);
        if (guards > 0) System.out.println("[mcshield] antiDebug injected " + guards + " guard calls");

        int cflow = new ControlFlow(config, seed).apply(model);
        if (cflow > 0) System.out.println("[mcshield] controlFlow inserted " + cflow + " opaque blocks");

        int enc = new StringEncryptor(config, seed, rt.stringsOwner).apply(model);
        if (enc > 0) System.out.println("[mcshield] stringEncryption encrypted " + enc + " literals");

        int opt = new Optimizer(config).apply(model);
        if (opt > 0) System.out.println("[mcshield] optimizer touched " + opt + " classes");

        int decomp = new AntiDecompile(config).apply(model);
        if (decomp > 0) System.out.println("[mcshield] antiDecompile added metadata noise to " + decomp + " items");

        CStyleDecoy fakeC = new CStyleDecoy(config, seed);
        int cstyle = fakeC.apply(model);
        if (cstyle > 0) System.out.println("[mcshield] fakeC applied C-style metadata to " + cstyle + " classes");

        ShadowVault.Result shadowVault = shellDelegate.enabled()
                ? new ShadowVault.Result(false, null, null, null, 0, null)
                : new ShadowVault(config, seed).apply(model, mapping, generatedClasses, generatedResources);
        if (shadowVault.enabled()) {
            System.out.println("[mcshield] shadowVault plugin.yml main -> " + shadowVault.publicOwner().replace('/', '.')
                    + " (protected classes=" + shadowVault.protectedClasses() + ")");
        }

        String nativeShellOwner = shellDelegate.enabled() ? shellDelegate.publicOwner() : (shadowVault.enabled() ? shadowVault.publicOwner() : (shadowBoot.enabled() ? shadowBoot.publicOwner() : null));
        int nativeGuard = new NativeGuard(config).apply(generatedClasses, generatedResources, nativeShellOwner);
        if (nativeGuard > 0) System.out.println("[mcshield] nativeGuard injected optional native probe");

        generatedClasses.putAll(new DeadCode(config, seed).generate());
        Map<String, byte[]> javaPluginDecoys = new JavaPluginDecoys(config, seed).generate();
        generatedClasses.putAll(javaPluginDecoys);
        if (!javaPluginDecoys.isEmpty()) System.out.println("[mcshield] javaPluginDecoys generated " + javaPluginDecoys.size() + " fake JavaPlugin entries");
        DecoyTree decoyTree = new DecoyTree(config, seed);
        Map<String, byte[]> decoyClasses = decoyTree.classes();
        Map<String, byte[]> decoyResources = decoyTree.resources();
        generatedClasses.putAll(decoyClasses);
        generatedClasses.putAll(runtimeHelpers(config, rt));
        generatedResources.putAll(new Watermark(config).resources());
        generatedResources.putAll(fakeC.resources());
        generatedResources.putAll(decoyResources);
        if (!decoyClasses.isEmpty() || !decoyResources.isEmpty()) {
            System.out.println("[mcshield] decoyTree generated classes=" + decoyClasses.size() + ", resources=" + decoyResources.size());
        }

        Map<String, String> remap = mapping.fullMap();
        Map<String, String> yamlRemap = shellDelegate.enabled() ? shellDelegate.yamlRemap() : (shadowVault.enabled() ? shadowVault.yamlRemap() : (shadowBoot.enabled() ? shadowBoot.yamlRemap() : (entryProxy.enabled() ? entryProxy.yamlRemap() : remap)));
        JarIO.write(cli.output, model, config, remap, yamlRemap, generatedClasses, generatedResources);
        if (config.bool("mapping.writeFile", true)) writeMapping(cli.output, mapping);
        System.out.println("[mcshield] done: " + cli.output);
        System.out.println("[mcshield] renamed classes=" + mapping.classMap.size() + ", members=" + mapping.memberMap.size() + ", generated classes=" + generatedClasses.size());
    }

    private static void printMainRemap(JarModel model, MappingContext mapping) {
        if (model.pluginMainFqn == null) return;
        String oldInternal = model.pluginMainFqn.replace('.', '/');
        String mapped = mapping.classMap.get(oldInternal);
        if (mapped != null) System.out.println("[mcshield] real main class will become: " + mapped.replace('/', '.'));
    }

    private static Map<String, byte[]> runtimeHelpers(ObfConfig config, RuntimeOwners rt) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<>();
        boolean needStrings = config.enabled("stringEncryption", true) || config.enabled("referenceReflection", true) || config.enabled("fieldReflection", false) || config.bool("shellDelegate.encryptDelegateStrings", false);
        boolean needRef = config.enabled("referenceReflection", true) || config.enabled("fieldReflection", false);
        boolean needGuard = config.enabled("antiDebug", false);
        if (needStrings) out.put(rt.stringsOwner, JarIO.remapClassBytes(JarIO.classResource(StringEncryptor.BASE_OWNER), StringEncryptor.BASE_OWNER, rt.stringsOwner));
        if (needRef) out.put(rt.refOwner, JarIO.remapClassBytes(JarIO.classResource(ReferenceReflection.BASE_REF_OWNER), ReferenceReflection.BASE_REF_OWNER, rt.refOwner));
        if (needGuard) out.put(rt.guardOwner, JarIO.remapClassBytes(JarIO.classResource(AntiDebug.BASE_OWNER), AntiDebug.BASE_OWNER, rt.guardOwner));
        return out;
    }

    private static void writeMapping(Path output, MappingContext ctx) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# McShield mapping\n");
        for (Map.Entry<String, String> e : ctx.classMap.entrySet()) sb.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
        for (Map.Entry<String, String> e : ctx.memberMap.entrySet()) sb.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
        Files.writeString(Path.of(output.toString() + ".map"), sb.toString(), StandardCharsets.UTF_8);
    }

    private static void printHelp() {
        System.out.println("McShield Obfuscator for Bukkit/Paper plugins");
        System.out.println("Usage: java -jar mcshield-1.0.jar <input.jar> <output.jar> -config obf.yml [-lib libsFolder]");
        System.out.println("Example: java -jar mcshield-1.0.jar MyPlugin.jar MyPlugin-obf.jar -config config/mcshield-1.0-normal.yml -lib ./libs");
    }

    private record RuntimeOwners(String stringsOwner, String refOwner, String guardOwner, String wrapperOwner) {
        static RuntimeOwners from(ObfConfig config) {
            String pkg = config.string("runtime.package", "x/rt").replace('.', '/');
            while (pkg.startsWith("/")) pkg = pkg.substring(1);
            while (pkg.endsWith("/")) pkg = pkg.substring(0, pkg.length() - 1);
            String strings = config.string("runtime.stringsClass", "S");
            String ref = config.string("runtime.refClass", "R");
            String guard = config.string("runtime.guardClass", "G");
            String wrapper = config.string("runtime.wrapperClass", "P");
            return new RuntimeOwners(join(pkg, strings), join(pkg, ref), join(pkg, guard), join(pkg, wrapper));
        }

        private static String join(String pkg, String leaf) {
            String x = leaf == null || leaf.isBlank() ? "X" : leaf.replace('.', '/');
            while (x.startsWith("/")) x = x.substring(1);
            return pkg.isEmpty() ? x : pkg + "/" + x;
        }
    }

    private static final class Cli {
        final Path input;
        final Path output;
        final Path config;
        final Path lib;
        final boolean help;

        private Cli(Path input, Path output, Path config, Path lib, boolean help) {
            this.input = input; this.output = output; this.config = config; this.lib = lib; this.help = help;
        }

        static Cli parse(String[] args) {
            if (args.length == 0 || Arrays.asList(args).contains("-h") || Arrays.asList(args).contains("--help")) {
                return new Cli(null, null, null, null, true);
            }
            if (args.length < 2) throw new IllegalArgumentException("Need input and output jar. Use --help.");
            Path in = Path.of(args[0]);
            Path out = Path.of(args[1]);
            Path cfg = Path.of("obf.yml");
            Path lib = null;
            for (int i = 2; i < args.length; i++) {
                switch (args[i]) {
                    case "-config", "--config" -> cfg = Path.of(args[++i]);
                    case "-lib", "--lib", "-li" -> lib = Path.of(args[++i]);
                    default -> throw new IllegalArgumentException("Unknown arg: " + args[i]);
                }
            }
            return new Cli(in, out, cfg, lib, false);
        }
    }
}
