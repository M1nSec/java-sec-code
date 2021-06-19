package com.p2hm1n.javabasics.classloader;

/**
 * 反射动态加载一个类对象
 * 会输出 hello world
 */
public class LoadClass01 {
    public static void main(String[] args) throws Exception {
        Class clz = Class.forName("com.p2hm1n.javabasics.classloader.HelloWorld");
        System.out.println(clz);
    }
}
