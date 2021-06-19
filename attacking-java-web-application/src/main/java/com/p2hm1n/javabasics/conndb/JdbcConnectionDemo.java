package com.p2hm1n.javabasics.conndb;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * 传统的Web应用的数据库配置信息一般都是存放在WEB-INF目录下的*.properties、*.yml、*.xml中
 * 如果是Spring Boot项目的话一般都会存储在jar包中的src/main/resources/目录下
 * 常见的存储数据库配置信息的文件路径如：WEB-INF/applicationContext.xml、WEB-INF/hibernate.cfg.xml、WEB-INF/jdbc/jdbc.properties
 * 一般情况下使用find命令加关键字可以轻松的找出来，如查找Mysql配置信息: find 路径 -type f |xargs grep "com.mysql.jdbc.Driver"
 */
public class JdbcConnectionDemo {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        String CLASS_NAME = "com.mysql.jdbc.Driver";
        String URL = "jdbc:mysql://localhost:3306/mysql";
        String USERNAME = "root";
        String PASSWORD = "";

        Class.forName(CLASS_NAME);// 注册JDBC驱动类
        Connection connection = DriverManager.getConnection(URL, USERNAME, PASSWORD);
        System.out.println(connection);
    }
}
