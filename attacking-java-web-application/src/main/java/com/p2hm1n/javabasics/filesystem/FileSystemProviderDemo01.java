package com.p2hm1n.javabasics.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileSystemProviderDemo01 {
    public static void main(String[] args) {
        // 定义读取的文件路径
        Path path = Paths.get("/etc/passwd");

        try {
            byte[] bytes = Files.readAllBytes(path);
            System.out.println(new String(bytes));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
