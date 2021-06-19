package com.p2hm1n.javabasics.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 文件名空截断
 * 受空字节截断影响的JDK版本范围:JDK<1.7.40
 * 测试环境 JDK 7u21
 * 利用场景 Java空字节截断利用场景最常见的利用场景就是文件上传时后端获取文件名后使用了endWith、正则使用如:.(jpg|png|gif)$验证文件名后缀合法性且文件名最终原样保存,同理文件删除(delete)、获取文件路径(getCanonicalPath)、创建文件(createNewFile)、文件重命名(renameTo)等方法也可适用。
 * 修复方案 最简单直接的方式就是升级JDK，如果担心升级JDK出现兼容性问题可在文件操作时检测下文件名中是否包含空字节，如JDK的修复方式:fileName.indexOf('\u0000')即可。
 */
public class FIleNameTruncate {
    public static void main(String[] args) {
        try {
            String fileName = "/tmp/null-bytes.txt\u0000.jpg";
            FileOutputStream fos = new FileOutputStream(new File(fileName));
            fos.write("Test".getBytes());
            fos.flush();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

