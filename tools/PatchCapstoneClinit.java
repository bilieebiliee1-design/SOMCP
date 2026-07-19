import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

public final class PatchCapstoneClinit implements Opcodes {
    public static void main(String[] args) throws Exception {
        File input = new File(args[0]);
        File output = new File(args[1]);
        try (JarFile jar = new JarFile(input); JarOutputStream jos = new JarOutputStream(new FileOutputStream(output))) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (isNativeResource(entry.getName())) continue;
                byte[] data = jar.getInputStream(entry).readAllBytes();
                JarEntry next = new JarEntry(entry.getName());
                jos.putNextEntry(next);
                if (entry.getName().equals("capstone/Capstone.class")) {
                    jos.write(patch(data));
                } else {
                    jos.write(data);
                }
                jos.closeEntry();
            }
        }
    }

    private static boolean isNativeResource(String name) {
        return name.endsWith(".so") || name.endsWith(".dylib") || name.endsWith(".dll");
    }

    private static byte[] patch(byte[] data) {
        ClassReader reader = new ClassReader(data);
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        reader.accept(new ClassVisitor(ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!name.equals("<clinit>")) return delegate;
                return new MethodVisitor(ASM9, delegate) {
                    @Override
                    public void visitCode() {
                        Label start = new Label();
                        Label end = new Label();
                        Label handler = new Label();
                        Label done = new Label();
                        mv.visitCode();
                        mv.visitInsn(ICONST_0);
                        mv.visitTypeInsn(ANEWARRAY, "capstone/Capstone$CsInsn");
                        mv.visitFieldInsn(PUTSTATIC, "capstone/Capstone", "EMPTY_INSN", "[Lcapstone/Capstone$CsInsn;");
                        mv.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
                        mv.visitLabel(start);
                        mv.visitLdcInsn("capstone");
                        mv.visitLdcInsn(org.objectweb.asm.Type.getType("Lcapstone/Capstone$CS;"));
                        mv.visitMethodInsn(INVOKESTATIC, "com/sun/jna/Native", "loadLibrary", "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;", false);
                        mv.visitTypeInsn(CHECKCAST, "capstone/Capstone$CS");
                        mv.visitFieldInsn(PUTSTATIC, "capstone/Capstone", "cs", "Lcapstone/Capstone$CS;");
                        mv.visitLabel(end);
                        mv.visitJumpInsn(GOTO, done);
                        mv.visitLabel(handler);
                        mv.visitVarInsn(ASTORE, 0);
                        mv.visitTypeInsn(NEW, "java/lang/IllegalStateException");
                        mv.visitInsn(DUP);
                        mv.visitLdcInsn("load capstone library failed.");
                        mv.visitVarInsn(ALOAD, 0);
                        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", false);
                        mv.visitInsn(ATHROW);
                        mv.visitLabel(done);
                        mv.visitInsn(RETURN);
                        mv.visitMaxs(0, 0);
                        mv.visitEnd();
                    }

                    @Override public void visitInsn(int opcode) {}
                    @Override public void visitIntInsn(int opcode, int operand) {}
                    @Override public void visitVarInsn(int opcode, int var) {}
                    @Override public void visitTypeInsn(int opcode, String type) {}
                    @Override public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {}
                    @Override public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {}
                    @Override public void visitJumpInsn(int opcode, Label label) {}
                    @Override public void visitLabel(Label label) {}
                    @Override public void visitLdcInsn(Object value) {}
                    @Override public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {}
                    @Override public void visitMaxs(int maxStack, int maxLocals) {}
                    @Override public void visitEnd() {}
                };
            }
        }, 0);
        return writer.toByteArray();
    }
}
