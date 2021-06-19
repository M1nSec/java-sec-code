package com.p2hm1n.javabasics.localrce;

import java.io.IOException;

/**
 * Runtime 命令执行
 */
public class RuntimeDemo01 {
    public static void main(String[] args) throws IOException {
        Runtime.getRuntime().exec("open -a Calculator");
    }
}
