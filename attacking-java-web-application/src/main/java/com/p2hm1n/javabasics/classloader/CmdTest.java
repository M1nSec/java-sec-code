package com.p2hm1n.javabasics.classloader;

import java.io.IOException;

public class CmdTest {
    public Process exec(String cmd) throws IOException {
        Process process = java.lang.Runtime.getRuntime().exec(cmd);
        return process;
    }
}
