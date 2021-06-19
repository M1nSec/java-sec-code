package com.p2hm1n.javabasics.localrce;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Map;

public class ProcessImplDemo {
    public static void main(String[] args) throws Exception {
        String[] cmds = {"whoami"};
        Class clz = Class.forName("java.lang.ProcessImpl");
        Method method = clz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
        method.setAccessible(true);
        Process procexec = (Process) method.invoke(null,cmds, null, ".", null, true);
        InputStream ins = procexec.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] bytes = new byte[1024];
        int size;
        while ((size = ins.read(bytes)) > 0 ){
            bos.write(bytes, 0, size);
        }
        System.out.println(bos.toString());
    }
}
