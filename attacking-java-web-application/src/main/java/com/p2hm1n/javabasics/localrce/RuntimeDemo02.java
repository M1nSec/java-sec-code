package com.p2hm1n.javabasics.localrce;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Runtime 命令执行
 * 有回显
 */
public class RuntimeDemo02 {
    public static void main(String[] args) throws IOException {
        Process process = Runtime.getRuntime().exec("whoami");
        InputStream in = process.getInputStream();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int a = -1;

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }

        System.out.println(new String(baos.toByteArray()));

    }
}
