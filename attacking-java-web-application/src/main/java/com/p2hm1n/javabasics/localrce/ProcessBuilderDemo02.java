package com.p2hm1n.javabasics.localrce;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * ProcessBuilder 命令执行
 * 通过 command 方法污染 ProcessBuilder 对象，不通过 new ProcessBuilder 的时候传参
 */
public class ProcessBuilderDemo02 {
    public static void main(String[] args) throws Exception {
        ProcessBuilder p1 = new ProcessBuilder();
        p1.command("whoami");
        InputStream in = p1.start().getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int a = -1;

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }
        System.out.println(new String(baos.toByteArray()));
    }
}
