package com.p2hm1n.javabasics.classloader;


/**
 * 自定义 classloader 加载 class
 */
public class TestClassLoader extends ClassLoader {
    // HelloWorld类名
    private static String testClassName = "com.p2hm1n.javabasics.classloader.HelloWorld";

    // HelloWorld类字节码
    private static byte[] testClassBytes = new byte[]{112, 97, 99, 107, 97, 103, 101, 32, 99, 111, 109, 46, 112, 50, 104, 109, 49, 110, 46, 106, 97, 118, 97, 98, 97, 115, 105, 99, 115, 46, 99, 108, 97, 115, 115, 108, 111, 97, 100, 101, 114, 59, 10, 10, 112, 117, 98, 108, 105, 99, 32, 99, 108, 97, 115, 115, 32, 72, 101, 108, 108, 111, 87, 111, 114, 108, 100, 32, 123, 10, 32, 32, 32, 32, 112, 117, 98, 108, 105, 99, 32, 115, 116, 97, 116, 105, 99, 32, 118, 111, 105, 100, 32, 109, 97, 105, 110, 40, 83, 116, 114, 105, 110, 103, 91, 93, 32, 97, 114, 103, 115, 41, 32, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 83, 121, 115, 116, 101, 109, 46, 111, 117, 116, 46, 112, 114, 105, 110, 116, 108, 110, 40, 34, 116, 101, 115, 116, 34, 41, 59, 10, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 115, 116, 97, 116, 105, 99, 32, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 83, 121, 115, 116, 101, 109, 46, 111, 117, 116, 46, 112, 114, 105, 110, 116, 108, 110, 40, 34, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 34, 41, 59, 10, 32, 32, 32, 32, 125, 10, 125, 10};

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        // 只处理TestHelloWorld类
        if (name.equals(testClassName)) {
            // 调用JVM的native方法定义TestHelloWorld类
            return defineClass(testClassName, testClassBytes, 0, testClassBytes.length);
        }

        return super.findClass(name);
    }

    public static void main(String[] args) {
        // 创建自定义的类加载器
        TestClassLoader loader = new TestClassLoader();

        try {
            // 使用自定义的类加载器加载TestHelloWorld类
            Class testClass = loader.loadClass(testClassName);

            // 反射创建TestHelloWorld类，等价于 TestHelloWorld t = new TestHelloWorld();
            Object testInstance = testClass.newInstance();

            System.out.println(testInstance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}