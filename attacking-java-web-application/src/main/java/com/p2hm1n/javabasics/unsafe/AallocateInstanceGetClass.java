package com.p2hm1n.javabasics.unsafe;

import com.p2hm1n.javabasics.classloader.HelloWorld;
import sun.misc.Unsafe;

import java.lang.reflect.Constructor;

/**
 * 因为某种原因我们不能直接通过反射的方式去创建 HelloWorld 类实例
 * 使用 Unsafe 的 allocateInstance 方法可以绕过这个限制
 */
public class AallocateInstanceGetClass {
    public static void main(String[] args) throws Exception{
        Constructor constructor = Unsafe.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        Unsafe unsafe1 = (Unsafe) constructor.newInstance();
        HelloWorld test = (HelloWorld) unsafe1.allocateInstance(HelloWorld.class);
    }
}
