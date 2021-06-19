package com.p2hm1n.javabasics.unsafe;

import sun.misc.Unsafe;

import java.lang.reflect.Field;

/**
 * 既然无法直接通过Unsafe.getUnsafe()的方式调用，那么可以使用反射的方式去获取Unsafe类实例
 * 反射获取Unsafe类实例代码片段
 */
public class GetUnsafeField {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException {
        // 反射获取Unsafe的theUnsafe成员变量
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");

        // 反射设置theUnsafe访问权限
        theUnsafeField.setAccessible(true);

        // 反射获取theUnsafe成员变量值
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);
        System.out.println(unsafe);


    }
}
