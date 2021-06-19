package com.p2hm1n.javabasics.unsafe;

import sun.misc.Unsafe;

import java.lang.reflect.Constructor;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

/**
 * 如果ClassLoader被限制的情况下我们还可以使用Unsafe的defineClass方法来向JVM中注册一个类
 * Unsafe提供了一个通过传入类名、类字节码的方式就可以定义类的defineClass方法
 * 使用场景 https://www.javaweb.org/?p=1873
 */
public class UnsafeDefineClass {
    public static void main(String[] args) throws Exception{
        // Test class ptah,创建一个不存在的 Test 类
        final String testClassPath = "com.p2hm1n.javabasics.random.Test";

        Class clazz = null;
        try {
            // 反射调用下,如果这个类已经被声明了就没必要再创建了
            clazz = Class.forName(testClassPath);
        } catch (ClassNotFoundException e) {
            // Test 字节码
            byte[] testClassBytes = new byte[]{-54, -2, -70, -66, 0, 0, 0, 52, 0, 32, 10, 0, 7, 0, 17, 8, 0, 18, 9, 0, 19, 0, 20, 8, 0, 21, 10, 0, 22, 0, 23, 7, 0, 24, 7, 0, 25, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 4, 69, 99, 104, 111, 1, 0, 20, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 8, 60, 99, 108, 105, 110, 105, 116, 62, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 9, 84, 101, 115, 116, 46, 106, 97, 118, 97, 12, 0, 8, 0, 9, 1, 0, 4, 101, 99, 104, 111, 7, 0, 26, 12, 0, 27, 0, 28, 1, 0, 4, 84, 101, 115, 116, 7, 0, 29, 12, 0, 30, 0, 31, 1, 0, 33, 99, 111, 109, 47, 112, 50, 104, 109, 49, 110, 47, 106, 97, 118, 97, 98, 97, 115, 105, 99, 115, 47, 114, 97, 110, 100, 111, 109, 47, 84, 101, 115, 116, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 121, 115, 116, 101, 109, 1, 0, 3, 111, 117, 116, 1, 0, 21, 76, 106, 97, 118, 97, 47, 105, 111, 47, 80, 114, 105, 110, 116, 83, 116, 114, 101, 97, 109, 59, 1, 0, 19, 106, 97, 118, 97, 47, 105, 111, 47, 80, 114, 105, 110, 116, 83, 116, 114, 101, 97, 109, 1, 0, 7, 112, 114, 105, 110, 116, 108, 110, 1, 0, 21, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 86, 0, 33, 0, 6, 0, 7, 0, 0, 0, 0, 0, 3, 0, 1, 0, 8, 0, 9, 0, 1, 0, 10, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 11, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 1, 0, 12, 0, 13, 0, 1, 0, 10, 0, 0, 0, 27, 0, 1, 0, 1, 0, 0, 0, 3, 18, 2, -80, 0, 0, 0, 1, 0, 11, 0, 0, 0, 6, 0, 1, 0, 0, 0, 8, 0, 8, 0, 14, 0, 9, 0, 1, 0, 10, 0, 0, 0, 37, 0, 2, 0, 0, 0, 0, 0, 9, -78, 0, 3, 18, 4, -74, 0, 5, -79, 0, 0, 0, 1, 0, 11, 0, 0, 0, 10, 0, 2, 0, 0, 0, 5, 0, 8, 0, 6, 0, 1, 0, 15, 0, 0, 0, 2, 0, 16};
            // 获取系统的类加载器
            ClassLoader classLoader = ClassLoader.getSystemClassLoader();

            // 创建默认的保护域
            ProtectionDomain domain = new ProtectionDomain(
                    new CodeSource(null, (Certificate[]) null), null, classLoader, null
            );
            Constructor constructor = Unsafe.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            Unsafe unsafe1 = (Unsafe) constructor.newInstance();

            clazz = unsafe1.defineClass(testClassPath, testClassBytes, 0, 495, classLoader, domain);
            System.out.println(clazz);
        }
    }
}
