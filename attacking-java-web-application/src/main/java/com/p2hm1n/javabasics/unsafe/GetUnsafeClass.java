package com.p2hm1n.javabasics.unsafe;

import sun.misc.Unsafe;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * 既然无法直接通过Unsafe.getUnsafe()的方式调用，那么可以使用反射的方式去获取Unsafe类实例
 * 反射创建Unsafe类实例的方式去获取Unsafe对象
 */
public class GetUnsafeClass {
    public static void main(String[] args) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        // 获取Unsafe无参构造方法
        Constructor constructor = Unsafe.class.getDeclaredConstructor();

        // 修改构造方法访问权限
        constructor.setAccessible(true);

        // 反射创建Unsafe类实例，等价于 Unsafe unsafe1 = new Unsafe();
        Unsafe unsafe1 = (Unsafe) constructor.newInstance();
        System.out.println(unsafe1);
    }
}
