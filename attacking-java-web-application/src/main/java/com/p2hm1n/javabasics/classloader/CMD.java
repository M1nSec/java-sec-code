package com.p2hm1n.javabasics.classloader;

import java.io.IOException;

/**
 * URLClassLoader 使用的远程 CMD jar 的 java 文件
 */
public class CMD {
    public static Process exec(String cmd) throws IOException {
        return Runtime.getRuntime().exec(cmd);
    }
}
