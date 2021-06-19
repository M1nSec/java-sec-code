package com.p2hm1n.javabasics.classloader;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * URLClassLoader 加载远程资源
 */
public class TestURLClassLoader {
    public static void main(String[] args) {
        try {
            // 定义远程加载的jar路径
            URL url = new URL("http://localhost:8888/CMD.jar");

            // 创建URLClassLoader对象，并加载远程jar包
            URLClassLoader ucl = new URLClassLoader(new URL[]{url});

            // 定义需要执行的系统命令
            String cmd = "open -a Calculator";

            // 通过URLClassLoader加载远程jar包中的CMD类
            Class cmdClass = ucl.loadClass("CMD");

            // 调用CMD类中的exec方法，等价于: Process process = CMD.exec("whoami");
            Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
