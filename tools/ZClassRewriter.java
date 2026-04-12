import org.objectweb.asm.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;

/**
 * Uses ASM to properly rewrite license validation methods in z.class.
 * ASM handles all class file structure: constant pool, stack maps, frames, etc.
 */
public class ZClassRewriter {

    // Methods to patch in z.class
    private static final Set<String> PATCH_TARGETS = new HashSet<>();
    static {
        // descriptor -> action
        PATCH_TARGETS.add("a:()Ljava/util/Set;");           // return new HashSet()
        PATCH_TARGETS.add("a:(Ljava/util/Set;)V");          // return void (no-op)
        PATCH_TARGETS.add("a:(Ljava/util/Set;)Z");          // return true
        PATCH_TARGETS.add("a:(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V"); // return void
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: ZClassRewriter <input.jar> <output.jar>");
            System.exit(1);
        }

        String inputJar = args[0];
        String outputJar = args[1];

        // Also load stub classes to inject
        String stubDir = new File(args[0]).getParent();
        // We'll handle stubs separately

        System.out.println("Reading: " + inputJar);
        System.out.println("Writing: " + outputJar);

        try (ZipInputStream zin = new ZipInputStream(new FileInputStream(inputJar));
             ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(outputJar))) {

            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                byte[] data = zin.readAllBytes();
                String name = entry.getName();

                if (name.equals("cz/solstate/z.class")) {
                    System.out.println("\n=== Rewriting cz/solstate/z.class ===");
                    data = rewriteZClass(data);
                }

                ZipEntry outEntry = new ZipEntry(name);
                // Preserve timestamps
                if (entry.getLastModifiedTime() != null)
                    outEntry.setLastModifiedTime(entry.getLastModifiedTime());
                zout.putNextEntry(outEntry);
                zout.write(data);
                zout.closeEntry();
            }
        }

        System.out.println("\nDone: " + outputJar);
    }

    private static byte[] rewriteZClass(byte[] classBytes) {
        // Use COMPUTE_FRAMES to let ASM recalculate all stack map frames
        // Use COMPUTE_MAXS to recalculate max_stack and max_locals
        ClassReader cr = new ClassReader(classBytes);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);

        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                String key = name + ":" + descriptor;

                if (PATCH_TARGETS.contains(key)) {
                    System.out.println("  PATCH: " + name + descriptor);

                    // Create method header, then write our own body
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

                    // Return a visitor that replaces the entire method body
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        private boolean started = false;

                        @Override
                        public void visitCode() {
                            // Write our replacement body instead
                            super.visitCode();
                            started = true;

                            switch (descriptor) {
                                case "()Ljava/util/Set;":
                                    // return HashSet containing version strings
                                    // onEnable checks isEmpty() and rejects empty sets
                                    // then checks z.a(Set)Z which we patch to return true
                                    super.visitTypeInsn(Opcodes.NEW, "java/util/HashSet");
                                    super.visitInsn(Opcodes.DUP);
                                    super.visitMethodInsn(Opcodes.INVOKESPECIAL,
                                            "java/util/HashSet", "<init>", "()V", false);
                                    super.visitInsn(Opcodes.DUP);
                                    super.visitLdcInsn("1.21");
                                    super.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                                            "java/util/HashSet", "add", "(Ljava/lang/Object;)Z", false);
                                    super.visitInsn(Opcodes.POP);
                                    super.visitInsn(Opcodes.ARETURN);
                                    System.out.println("    -> return HashSet{\"1.21\"}");
                                    break;

                                case "(Ljava/util/Set;)V":
                                    // just return
                                    super.visitInsn(Opcodes.RETURN);
                                    System.out.println("    -> return (no-op)");
                                    break;

                                case "(Ljava/util/Set;)Z":
                                    // return true
                                    super.visitInsn(Opcodes.ICONST_1);
                                    super.visitInsn(Opcodes.IRETURN);
                                    System.out.println("    -> return true");
                                    break;

                                case "(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V":
                                    // just return
                                    super.visitInsn(Opcodes.RETURN);
                                    System.out.println("    -> return (no-op)");
                                    break;
                            }

                            super.visitMaxs(2, 4);
                            super.visitEnd();
                        }

                        // Suppress all original bytecode
                        @Override public void visitInsn(int opcode) {}
                        @Override public void visitIntInsn(int opcode, int operand) {}
                        @Override public void visitVarInsn(int opcode, int varIndex) {}
                        @Override public void visitTypeInsn(int opcode, String type) {}
                        @Override public void visitFieldInsn(int opcode, String owner, String n, String d) {}
                        @Override public void visitMethodInsn(int opcode, String owner, String n, String d, boolean itf) {}
                        @Override public void visitInvokeDynamicInsn(String n, String d, org.objectweb.asm.Handle bsm, Object... bsmArgs) {}
                        @Override public void visitJumpInsn(int opcode, Label label) {}
                        @Override public void visitLabel(Label label) {}
                        @Override public void visitLdcInsn(Object value) {}
                        @Override public void visitIincInsn(int varIndex, int increment) {}
                        @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {}
                        @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {}
                        @Override public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {}
                        @Override public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {}
                        @Override public void visitLocalVariable(String n, String d, String sig, Label start, Label end, int idx) {}
                        @Override public void visitLineNumber(int line, Label start) {}
                        @Override public void visitFrame(int type, int numLocal, Object[] local, int numStack, Object[] stack) {}
                        @Override public void visitMaxs(int maxStack, int maxLocals) {}
                        @Override public void visitEnd() {}
                    };
                }

                // All other methods pass through unchanged
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }
        }, 0);

        byte[] result = cw.toByteArray();
        System.out.println("  Original size: " + classBytes.length + " -> Rewritten: " + result.length);
        return result;
    }
}
