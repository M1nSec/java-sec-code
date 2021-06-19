package com.p2hm1n.javabasics.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileSystemProviderDemo02 {
    public static void main(String[] args) {
        // 定义读取的文件路径
        Path path = Paths.get("/tmp/test.txt");

        // 定义待写入文件内容
        String content = "Hello World.";

        try {
            // 写入内容二进制到文件
            Files.write(path, content.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
