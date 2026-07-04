/*
 * MIT License
 *
 * Project URL: https://github.com/jar-analyzer/jar-obfuscator
 *
 * Copyright (c) 2024-2026 4ra1n (https://github.com/4ra1n)
 *
 * This project is distributed under the MIT license.
 *
 * https://opensource.org/license/mit
 */

package me.n1ar4.jar.obfuscator.templates;

import me.n1ar4.jar.obfuscator.Const;
import org.objectweb.asm.*;

public class StringDecryptDump implements Opcodes {
    public static String AES_KEY = null;
    public static String className = null;
    public static String methodName = null;
    private static String keyName = null;
    private static final String CACHE_FIELD_NAME = "stringCache";

    public static void changeKEY() {
        AES_KEY = StringDecrypt.KEY;
    }

    public static void initName(String c, String m, String k) {
        String defaultClassName = "org/apache/commons/collections/list/AbstractHashMap";
        String defaultMethodName = "newMap";
        String defaultKeyName = "LiLiLLLiiiLLiiLLi";
        if (c == null || m == null || k == null) {
            className = defaultClassName;
            methodName = defaultMethodName;
            keyName = defaultKeyName;
            return;
        }
        c = c.replace(".", "/");
        if (c.isEmpty()) {
            className = defaultClassName;
        } else {
            className = c;
        }
        if (m.isEmpty()) {
            methodName = defaultMethodName;
        } else {
            methodName = m;
        }
        if (k.isEmpty()) {
            keyName = defaultKeyName;
        } else {
            keyName = k;
        }
    }

    public static byte[] dump() {
        ClassWriter classWriter = new ClassWriter(Const.WriterASMOptions);
        FieldVisitor fieldVisitor;
        MethodVisitor methodVisitor;
        classWriter.visit(V1_6, ACC_PUBLIC | ACC_SUPER, className, null, "java/lang/Object", null);
        
        {
            fieldVisitor = classWriter.visitField(ACC_PRIVATE | ACC_STATIC, keyName, "Ljava/lang/String;", null, null);
            fieldVisitor.visitEnd();
        }
        {
            fieldVisitor = classWriter.visitField(ACC_PRIVATE | ACC_FINAL | ACC_STATIC, "CHARSET", "Ljava/nio/charset/Charset;", null, null);
            fieldVisitor.visitEnd();
        }
        {
            // Inject the ConcurrentHashMap field into the target runtime class map
            fieldVisitor = classWriter.visitField(ACC_PRIVATE | ACC_FINAL | ACC_STATIC, CACHE_FIELD_NAME, "Ljava/util/concurrent/ConcurrentHashMap;", null, null);
            fieldVisitor.visitEnd();
        }
        
        {
            methodVisitor = classWriter.visitMethod(ACC_PUBLIC | ACC_STATIC, methodName, "(Ljava/lang/String;)Ljava/lang/String;", null, null);
            methodVisitor.visitCode();
            
            // --- CACHE LOOKUP OPTIMIZATION BLOCK START ---
            Label cacheMissLabel = new Label();
            methodVisitor.visitVarInsn(ALOAD, 0); // Load encrypted string parameter
            methodVisitor.visitJumpInsn(IFNULL, cacheMissLabel); // If null, skip cache
            
            methodVisitor.visitFieldInsn(GETSTATIC, className, CACHE_FIELD_NAME, "Ljava/util/concurrent/ConcurrentHashMap;");
            methodVisitor.visitVarInsn(ALOAD, 0);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/util/concurrent/ConcurrentHashMap", "get", "(Ljava/lang/Object;)Ljava/lang/Object;", false);
            methodVisitor.visitTypeInsn(CHECKCAST, "java/lang/String");
            methodVisitor.visitVarInsn(ASTORE, 1); // Store result in register index 1 temporary slot
            
            methodVisitor.visitVarInsn(ALOAD, 1);
            methodVisitor.visitJumpInsn(IFNULL, cacheMissLabel); // If not found in map cache, skip to standard decrypt logic
            methodVisitor.visitVarInsn(ALOAD, 1);
            methodVisitor.visitInsn(ARETURN); // Instant Cache Hit Return!
            methodVisitor.visitLabel(cacheMissLabel);
            // --- CACHE LOOKUP OPTIMIZATION BLOCK END ---

            Label label0 = new Label();
            Label label1 = new Label();
            Label label2 = new Label();
            methodVisitor.visitTryCatchBlock(label0, label1, label2, "java/lang/Exception");
            Label label3 = new Label();
            Label label4 = new Label();
            Label label5 = new Label();
            methodVisitor.visitTryCatchBlock(label3, label4, label5, "java/lang/Exception");
            Label label6 = new Label();
            Label label7 = new Label();
            Label label8 = new Label();
            methodVisitor.visitTryCatchBlock(label6, label7, label8, "java/lang/Exception");
            Label label9 = new Label();
            Label label10 = new Label();
            methodVisitor.visitTryCatchBlock(label9, label10, label8, "java/lang/Exception");
            methodVisitor.visitLabel(label6);

            methodVisitor.visitTypeInsn(NEW, "javax/crypto/spec/SecretKeySpec");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitFieldInsn(GETSTATIC, className, keyName, "Ljava/lang/String;");
            methodVisitor.visitFieldInsn(GETSTATIC, className, "CHARSET", "Ljava/nio/charset/Charset;");
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
            methodVisitor.visitLdcInsn("AES");
            methodVisitor.visitMethodInsn(INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V", false);
            methodVisitor.visitVarInsn(ASTORE, 1);
            Label label11 = new Label();
            methodVisitor.visitLabel(label11);

            methodVisitor.visitLdcInsn("AES");
            methodVisitor.visitMethodInsn(INVOKESTATIC, "javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false);
            methodVisitor.visitVarInsn(ASTORE, 2);
            Label label12 = new Label();
            methodVisitor.visitLabel(label12);

            methodVisitor.visitVarInsn(ALOAD, 2);
            methodVisitor.visitInsn(ICONST_2);
            methodVisitor.visitVarInsn(ALOAD, 1);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "javax/crypto/Cipher", "init", "(ILjava/security/Key;)V", false);
            Label label13 = new Label();
            methodVisitor.visitLabel(label13);

            methodVisitor.visitInsn(ACONST_NULL);
            methodVisitor.visitVarInsn(ASTORE, 4);
            methodVisitor.visitLabel(label0);

            methodVisitor.visitLdcInsn("java.util.Base64");
            methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false);
            methodVisitor.visitVarInsn(ASTORE, 3);
            Label label14 = new Label();
            methodVisitor.visitLabel(label14);

            methodVisitor.visitVarInsn(ALOAD, 3);
            methodVisitor.visitLdcInsn("getDecoder");
            methodVisitor.visitInsn(ACONST_NULL);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
            methodVisitor.visitVarInsn(ALOAD, 3);
            methodVisitor.visitInsn(ACONST_NULL);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
            methodVisitor.visitVarInsn(ASTORE, 5);
            Label label15 = new Label();
            methodVisitor.visitLabel(label15);

            methodVisitor.visitVarInsn(ALOAD, 5);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
            methodVisitor.visitLdcInsn("decode");
            methodVisitor.visitInsn(ICONST_1);
            methodVisitor.visitTypeInsn(ANEWARRAY, "java/lang/Class");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_0);
            methodVisitor.visitLdcInsn(Type.getType("Ljava/lang/String;"));
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
            methodVisitor.visitVarInsn(ALOAD, 5);
            methodVisitor.visitInsn(ICONST_1);
            methodVisitor.visitTypeInsn(ANEWARRAY, "java/lang/Object");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_0);
            methodVisitor.visitVarInsn(ALOAD, 0);
            methodVisitor.visitInsn(AASTORE);
            Label label16 = new Label();
            methodVisitor.visitLabel(label16);

            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
            methodVisitor.visitTypeInsn(CHECKCAST, "[B");
            methodVisitor.visitTypeInsn(CHECKCAST, "[B");
            methodVisitor.visitVarInsn(ASTORE, 4);
            methodVisitor.visitLabel(label1);

            methodVisitor.visitJumpInsn(GOTO, label9);
            methodVisitor.visitLabel(label2);

            methodVisitor.visitFrame(Opcodes.F_FULL, 5, new Object[]{"java/lang/String", "javax/crypto/spec/SecretKeySpec", "javax/crypto/Cipher", Opcodes.TOP, "[B"}, 1, new Object[]{"java/lang/Exception"});
            methodVisitor.visitVarInsn(ASTORE, 5);
            methodVisitor.visitLabel(label3);

            methodVisitor.visitLdcInsn("sun.misc.BASE64Decoder");
            methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false);
            methodVisitor.visitVarInsn(ASTORE, 3);
            Label label17 = new Label();
            methodVisitor.visitLabel(label17);

            methodVisitor.visitVarInsn(ALOAD, 3);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "newInstance", "()Ljava/lang/Object;", false);
            methodVisitor.visitVarInsn(ASTORE, 6);
            Label label18 = new Label();
            methodVisitor.visitLabel(label18);

            methodVisitor.visitVarInsn(ALOAD, 6);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
            methodVisitor.visitLdcInsn("decodeBuffer");
            methodVisitor.visitInsn(ICONST_1);
            methodVisitor.visitTypeInsn(ANEWARRAY, "java/lang/Class");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_0);
            methodVisitor.visitLdcInsn(Type.getType("Ljava/lang/String;"));
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
            methodVisitor.visitVarInsn(ALOAD, 6);
            methodVisitor.visitInsn(ICONST_1);
            methodVisitor.visitTypeInsn(ANEWARRAY, "java/lang/Object");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_0);
            methodVisitor.visitVarInsn(ALOAD, 0);
            methodVisitor.visitInsn(AASTORE);
            Label label19 = new Label();
            methodVisitor.visitLabel(label19);

            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
            methodVisitor.visitTypeInsn(CHECKCAST, "[B");
            methodVisitor.visitTypeInsn(CHECKCAST, "[B");
            methodVisitor.visitVarInsn(ASTORE, 4);
            methodVisitor.visitLabel(label4);

            methodVisitor.visitJumpInsn(GOTO, label9);
            methodVisitor.visitLabel(label5);

            methodVisitor.visitFrame(Opcodes.F_FULL, 6, new Object[]{"java/lang/String", "javax/crypto/spec/SecretKeySpec", "javax/crypto/Cipher", Opcodes.TOP, "[B", "java/lang/Exception"}, 1, new Object[]{"java/lang/Exception"});
            methodVisitor.visitVarInsn(ASTORE, 6);
            Label label20 = new Label();
            methodVisitor.visitLabel(label20);

            methodVisitor.visitLdcInsn("");
            methodVisitor.visitLabel(label7);
            methodVisitor.visitInsn(ARETURN);
            methodVisitor.visitLabel(label9);

            methodVisitor.visitFrame(Opcodes.F_FULL, 5, new Object[]{"java/lang/String", "javax/crypto/spec/SecretKeySpec", "javax/crypto/Cipher", "java/lang/Class", "[B"}, 0, new Object[]{});
            methodVisitor.visitVarInsn(ALOAD, 2);
            methodVisitor.visitVarInsn(ALOAD, 4);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "javax/crypto/Cipher", "doFinal", "([B)[B", false);
            methodVisitor.visitVarInsn(ASTORE, 5);
            Label label21 = new Label();
            methodVisitor.visitLabel(label21);

            methodVisitor.visitTypeInsn(NEW, "java/lang/String");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitVarInsn(ALOAD, 5);
            methodVisitor.visitFieldInsn(GETSTATIC, className, "CHARSET", "Ljava/nio/charset/Charset;");
            methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false);
            methodVisitor.visitVarInsn(ASTORE, 6); // Save decrypted string into temporary index 6
            
            // --- SAVE TO CACHE BEFORE RETURNING ---
            methodVisitor.visitFieldInsn(GETSTATIC, className, CACHE_FIELD_NAME, "Ljava/util/concurrent/ConcurrentHashMap;");
            methodVisitor.visitVarInsn(ALOAD, 0); // Original key
            methodVisitor.visitVarInsn(ALOAD, 6); // Decrypted string value
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/util/concurrent/ConcurrentHashMap", "putIfAbsent", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false);
            methodVisitor.visitInsn(POP); // Discard output value returned from putIfAbsent
            
            methodVisitor.visitVarInsn(ALOAD, 6);
            methodVisitor.visitLabel(label10);
            methodVisitor.visitInsn(ARETURN);
            methodVisitor.visitLabel(label8);

            methodVisitor.visitFrame(Opcodes.F_FULL, 1, new Object[]{"java/lang/String"}, 1, new Object[]{"java/lang/Exception"});
            methodVisitor.visitVarInsn(ASTORE, 1);
            Label label22 = new Label();
            methodVisitor.visitLabel(label22);

            methodVisitor.visitInsn(ACONST_NULL);
            methodVisitor.visitInsn(ARETURN);
            Label label23 = new Label();
            methodVisitor.visitLabel(label23);
            methodVisitor.visitMaxs(6, 8);
            methodVisitor.visitEnd();
        }
        {
            // Static Initializer block (<clinit>)
            methodVisitor = classWriter.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
            methodVisitor.visitCode();
            Label label0 = new Label();
            methodVisitor.visitLabel(label0);
            
            // Initialize ConcurrentHashMap: stringCache = new ConcurrentHashMap()
            methodVisitor.visitTypeInsn(NEW, "java/util/concurrent/ConcurrentHashMap");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/util/concurrent/ConcurrentHashMap", "<init>", "()V", false);
            methodVisitor.visitFieldInsn(PUTSTATIC, className, CACHE_FIELD_NAME, "Ljava/util/concurrent/ConcurrentHashMap;");
            
            methodVisitor.visitLdcInsn(AES_KEY);
            methodVisitor.visitFieldInsn(PUTSTATIC, className, keyName, "Ljava/lang/String;");
            Label label1 = new Label();
            methodVisitor.visitLabel(label1);
            methodVisitor.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
            methodVisitor.visitFieldInsn(PUTSTATIC, className, "CHARSET", "Ljava/nio/charset/Charset;");
            methodVisitor.visitInsn(RETURN);
            methodVisitor.visitMaxs(2, 0);
            methodVisitor.visitEnd();
        }
        classWriter.visitEnd();
        return classWriter.toByteArray();
    }
}
