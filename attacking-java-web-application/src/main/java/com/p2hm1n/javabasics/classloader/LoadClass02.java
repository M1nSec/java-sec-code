package com.p2hm1n.javabasics.classloader;

/**
 * classloader 加载一个类对象
 * 不会输出 hello world
 * ClassLoader.loadClass默认不会初始化类方法
 */
public class LoadClass02 {
    public static void main(String[] args) throws ClassNotFoundException {
        LoadClass02 clz = new LoadClass02();
        Class testClz = clz.getClass().getClassLoader().loadClass("com.p2hm1n.javabasics.classloader.HelloWorld");
        System.out.println(testClz);
    }
}
