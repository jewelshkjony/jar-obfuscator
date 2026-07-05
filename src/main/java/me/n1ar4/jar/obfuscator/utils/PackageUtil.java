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

package me.n1ar4.jar.obfuscator.utils;

import me.n1ar4.jar.obfuscator.base.ClassReference;
import me.n1ar4.jar.obfuscator.base.MethodReference;
import me.n1ar4.jar.obfuscator.config.BaseConfig;
import me.n1ar4.jar.obfuscator.core.AnalyzeEnv;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PackageUtil {
    private static final List<String> internalList = new ArrayList<>();

    public static void reset() {
        internalList.clear();
    }

    public static void buildInternalBlackList() {
        // JNI 的 CLASS 默认加到黑名单里面
        for (Map.Entry<ClassReference.Handle, List<MethodReference>> entry :
                AnalyzeEnv.methodsInClassMap.entrySet()) {
            String className = entry.getKey().getName();
            List<MethodReference> ref = entry.getValue();
            for (MethodReference m : ref) {
                int access = m.getAccess();
                if ((access & Opcodes.ACC_NATIVE) != 0) {
                    internalList.add(className);
                    break;
                }
            }
        }
    }

    public static boolean inBlackClass(String className, BaseConfig config) {
        className = className.replace(".", "/");

        // Use just one list for all rule types (Exact, *, and **)
        List<String> blackList = config.getClassBlackList();

        if (blackList != null && !blackList.isEmpty()) {
            for (String rule : blackList) {
                rule = rule.replace(".", "/");

                // Case 1: Deep Wildcard (e.g., com/jewel/**)
                if (rule.endsWith("/**")) {
                    String prefix = rule.substring(0, rule.length() - 3);
                    if (className.startsWith(prefix)) {
                        return true;
                    }
                } 
                // Case 2: Shallow Wildcard (e.g., com/jewel/fast/*)
                else if (rule.endsWith("/*")) {
                    String prefix = rule.substring(0, rule.length() - 2);
                    if (className.startsWith(prefix)) {
                        // Ensure they are in the exact same package depth level
                        long ruleSlashCount = rule.chars().filter(ch -> ch == '/').count();
                        long classSlashCount = className.chars().filter(ch -> ch == '/').count();
                        
                        // "com/jewel/fast/*" has 3 slashes. 
                        // "com/jewel/fast/Fast" also has 3 slashes -> MATCH
                        // "com/jewel/fast/build/Docs" has 4 slashes -> SKIPPED
                        if (ruleSlashCount == classSlashCount) {
                            return true;
                        }
                    }
                } 
                // Case 3: Exact Class Match (e.g., com/jewel/fast/Fast)
                else {
                    if (className.equals(rule)) {
                        return true;
                    }
                }
            }
        }

        // Internal JNI fallback safety check
        if (!internalList.isEmpty()) {
            for (String s : internalList) {
                s = s.replace(".", "/");
                if (className.equals(s)) {
                    return true;
                }
            }
        }
        return false;
    }
}
