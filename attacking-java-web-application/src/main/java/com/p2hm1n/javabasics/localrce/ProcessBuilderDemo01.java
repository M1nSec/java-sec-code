package com.p2hm1n.javabasics.localrce;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * ProcessBuilder 命令执行
 * 直接调用 start 方法
 */
public class ProcessBuilderDemo01 {
    public static void main(String[] args) throws Exception {
        InputStream in = new ProcessBuilder("whoami").start().getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int a = -1;

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }
        System.out.println(new String(baos.toByteArray()));
    }
}
