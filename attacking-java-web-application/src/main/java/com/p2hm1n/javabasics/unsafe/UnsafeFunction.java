package com.p2hm1n.javabasics.unsafe;

import java.lang.reflect.Field;
import java.security.ProtectionDomain;

/**
 * REF：https://tech.meituan.com/2019/02/14/talk-about-java-magic-class-unsafe.html
 * Unsafe提供的API大致可分为内存操作、CAS、Class相关、对象操作、线程调度、系统信息获取、内存屏障、数组操作等几类
 */
public class UnsafeFunction {
    /**
     * 线程调度
     */
    //取消阻塞线程
    public native void unpark(Object thread);
    //阻塞线程
    public native void park(boolean isAbsolute, long time);
    //获得对象锁（可重入锁）
    @Deprecated
    public native void monitorEnter(Object o);
    //释放对象锁
    @Deprecated
    public native void monitorExit(Object o);
    //尝试获取对象锁
    @Deprecated
    public native boolean tryMonitorEnter(Object o);

    /**
     * Class相关
     */
    //获取给定静态字段的内存地址偏移量，这个值对于给定的字段是唯一且固定不变的
    public native long staticFieldOffset(Field f);

    //获取一个静态类中给定字段的对象指针
    public native Object staticFieldBase(Field f);

    //判断是否需要初始化一个类，通常在获取一个类的静态属性的时候（因为一个类如果没初始化，它的静态属性也不会初始化）使用。 当且仅当ensureClassInitialized方法不生效时返回false。
    public native boolean shouldBeInitialized(Class<?> c);

    //检测给定的类是否已经初始化。通常在获取一个类的静态属性的时候（因为一个类如果没初始化，它的静态属性也不会初始化）使用。
    public native void ensureClassInitialized(Class<?> c);

    //定义一个类，此方法会跳过JVM的所有安全检查，默认情况下，ClassLoader（类加载器）和ProtectionDomain（保护域）实例来源于调用者
    public native Class<?> defineClass(String name, byte[] b, int off, int len, ClassLoader loader, ProtectionDomain protectionDomain);

    //定义一个匿名类
    public native Class<?> defineAnonymousClass(Class<?> hostClass, byte[] data, Object[] cpPatches);

    /**
     * 对象操作
     */
    //返回对象成员属性在内存地址相对于此对象的内存地址的偏移量
    public native long objectFieldOffset(Field f);

    //获得给定对象的指定地址偏移量的值，与此类似操作还有：getInt，getDouble，getLong，getChar等
    // public native Object getObject(Object o, long offset);

    //给定对象的指定地址偏移量设值，与此类似操作还有：putInt，putDouble，putLong，putChar等
    // public native void putObject(Object o, long offset, Object x);

    //从对象的指定偏移量处获取变量的引用，使用volatile的加载语义
    public native Object getObjectVolatile(Object o, long offset);

    //存储变量的引用到对象的指定的偏移量处，使用volatile的存储语义
    public native void putObjectVolatile(Object o, long offset, Object x);

    //有序、延迟版本的putObjectVolatile方法，不保证值的改变被其他线程立即看到。只有在field被volatile修饰符修饰时有效
    public native void putOrderedObject(Object o, long offset, Object x);

    //绕过构造方法、初始化代码来创建对象
    public native Object allocateInstance(Class<?> cls) throws InstantiationException;
}
