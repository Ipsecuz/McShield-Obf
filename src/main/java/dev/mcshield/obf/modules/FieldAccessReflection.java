package dev.mcshield.obf.modules;

import dev.mcshield.obf.config.ObfConfig;
import dev.mcshield.obf.io.ClassEntry;
import dev.mcshield.obf.io.JarModel;
import dev.mcshield.obf.util.Bytecode;
import dev.mcshield.obf.util.Wildcard;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.Type;
import jdk.internal.org.objectweb.asm.tree.AbstractInsnNode;
import jdk.internal.org.objectweb.asm.tree.FieldInsnNode;
import jdk.internal.org.objectweb.asm.tree.InsnList;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;

import java.util.HashMap;
import java.util.Map;

public final class FieldAccessReflection implements Opcodes {
    private final ObfConfig config;
    private final MappingContext mapping;
    private final String refOwner;
    private final String stringsOwner;
    private final boolean strongStrings;
    private final String fieldStringMode;

    public FieldAccessReflection(ObfConfig config, MappingContext mapping, String refOwner, String stringsOwner) {
        this.config = config;
        this.mapping = mapping;
        this.refOwner = refOwner;
        this.stringsOwner = stringsOwner;
        this.strongStrings = StringEncryptor.strongMode(config);
        this.fieldStringMode = config.string("fieldReflection.stringMode", strongStrings ? "indy" : "direct");
    }

    public int apply(JarModel model) {
        if (!config.enabled("fieldReflection", false)) return 0;
        Map<String, FieldMeta> fields = collectFields(model);
        int maxPerMethod = Math.max(0, config.integer("fieldReflection.maxPerMethod", 96));
        int changed = 0;
        for (ClassEntry ce : model.classes.values()) {
            if (Wildcard.any(ce.node.name, config.list("fieldReflection.skipClasses"))) continue;
            for (MethodNode mn : ce.node.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                int changedInMethod = 0;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
                    AbstractInsnNode next = insn.getNext();
                    if (insn instanceof FieldInsnNode fi && shouldReflect(fi, fields)) {
                        if (maxPerMethod > 0 && changedInMethod >= maxPerMethod) {
                            insn = next;
                            continue;
                        }
                        if (fi.getOpcode() == GETFIELD) {
                            mn.instructions.insert(fi, getFieldReplacement(fi));
                            mn.instructions.remove(fi);
                            if (StringEncryptor.usesIndy(fieldStringMode) && ce.node.version < V1_7) ce.node.version = V1_7;
                            changed++;
                            changedInMethod++;
                        } else if (fi.getOpcode() == PUTFIELD && config.bool("fieldReflection.rewriteWrites", true)) {
                            mn.instructions.insert(fi, putFieldReplacement(mn, fi));
                            mn.instructions.remove(fi);
                            if (StringEncryptor.usesIndy(fieldStringMode) && ce.node.version < V1_7) ce.node.version = V1_7;
                            changed++;
                            changedInMethod++;
                        }
                    }
                    insn = next;
                }
            }
        }
        return changed;
    }

    private Map<String, FieldMeta> collectFields(JarModel model) {
        Map<String, FieldMeta> out = new HashMap<>();
        for (ClassEntry ce : model.classes.values()) {
            ce.node.fields.forEach(fn -> out.put(ce.node.name + "." + fn.name, new FieldMeta(fn.access, fn.desc)));
        }
        return out;
    }

    private boolean shouldReflect(FieldInsnNode fi, Map<String, FieldMeta> fields) {
        if (fi.getOpcode() != GETFIELD && fi.getOpcode() != PUTFIELD) return false;
        FieldMeta meta = fields.get(fi.owner + "." + fi.name);
        if (meta == null) return false;
        if (config.bool("fieldReflection.renamedOnly", true) && !mapping.classMap.containsKey(fi.owner)) return false;
        if (config.bool("fieldReflection.privateOnly", true) && (meta.access & ACC_PRIVATE) == 0) return false;
        if ((meta.access & (ACC_TRANSIENT | ACC_VOLATILE)) != 0 && config.bool("fieldReflection.skipVolatileTransient", true)) return false;
        String sig = fi.owner.replace('/', '.') + "." + fi.name;
        if (Wildcard.any(sig, config.list("fieldReflection.skipFields")) || Wildcard.any(fi.name, config.list("fieldReflection.skipFieldNames"))) return false;
        return true;
    }

    private InsnList getFieldReplacement(FieldInsnNode fi) {
        InsnList il = new InsnList();
        addEncryptedString(il, finalOwner(fi.owner).replace('/', '.'));
        addEncryptedString(il, finalFieldName(fi));
        il.add(new MethodInsnNode(INVOKESTATIC, refOwner, "f", "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;", false));
        Bytecode.unboxOrCast(il, Type.getType(fi.desc));
        return il;
    }

    private InsnList putFieldReplacement(MethodNode mn, FieldInsnNode fi) {
        Type type = Type.getType(fi.desc);
        int valueLocal = mn.maxLocals;
        mn.maxLocals += Bytecode.sizeOf(type);
        int ownerLocal = mn.maxLocals;
        mn.maxLocals += 1;

        InsnList il = new InsnList();
        il.add(new VarInsnNode(Bytecode.storeOpcode(type), valueLocal));
        il.add(new VarInsnNode(ASTORE, ownerLocal));
        il.add(new VarInsnNode(ALOAD, ownerLocal));
        addEncryptedString(il, finalOwner(fi.owner).replace('/', '.'));
        addEncryptedString(il, finalFieldName(fi));
        il.add(new VarInsnNode(Bytecode.loadOpcode(type), valueLocal));
        Bytecode.box(il, type);
        il.add(new MethodInsnNode(INVOKESTATIC, refOwner, "p", "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V", false));
        return il;
    }

    private String finalOwner(String owner) {
        return mapping.classMap.getOrDefault(owner, owner);
    }

    private String finalFieldName(FieldInsnNode fi) {
        return mapping.memberMap.getOrDefault(fi.owner + "." + fi.name, fi.name);
    }

    private void addEncryptedString(InsnList il, String plain) {
        int keyA = (plain.hashCode() * 1315423911) | 1;
        int keyB = (plain.hashCode() ^ 0x45D9F3B) | 1;
        StringEncryptor.emitEncryptedString(il, plain, keyA, keyB, stringsOwner, fieldStringMode, "_");
    }

    private record FieldMeta(int access, String desc) {}
}
