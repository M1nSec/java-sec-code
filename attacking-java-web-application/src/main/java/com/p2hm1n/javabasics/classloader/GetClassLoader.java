package com.p2hm1n.javabasics.classloader;

/**
 * 获取 ClassLoader
 */
public class GetClassLoader {
    public static void main(String[] args) {
         // AppClassLoader是默认的类加载器，如果类加载时我们不指定类加载器的情况下，默认会使用AppClassLoader加载类
        System.out.println(ClassLoader.getSystemClassLoader());
        // java.io.File类被Bootstrap ClassLoader加载，被Bootstrap ClassLoader类加载器所加载的类的ClassLoader时候都会返回null
        System.out.println(java.io.File.class.getClassLoader());
    }
}
