package com.p2hm1n.javabasics.classloader;

import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * 将 Java 文件转换为 Bytes 数组
 */
public class FileConvertToByteArray {
    public static void main(String[] args) throws IOException {
        byte[] bFile = Files.readAllBytes(new File("/Users/p2hm1n/Desktop/demo/CmdTest.class").toPath());
        System.out.println(Arrays.toString(bFile));
        System.out.println(bFile.length);
    }
}
