package com.zyh.常见的Web攻击手段.文件类型判断;

import com.zyh.常用的安全算法.数字摘要.HexCode;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author yuanhao
 * @date 2018/6/16 16:37
 */
public class FileTypeDemo {

    public static void main(String[] args) throws IOException {
        String filePath = "D:\\hello.jpg";
        FileType fileType = getType(filePath);
        System.out.println(fileType);
    }

    /**
     * 读取文件头
     * @param filePath 文件路径
     * @return 文件头信息
     * @throws IOException IO异常
     */
    public static String getFileHeader(String filePath) throws IOException {
        byte[] b = new byte[28];
        InputStream inputStream = null;
        inputStream = new FileInputStream(filePath);
        inputStream.read(b, 0, 28);
        inputStream.close();
        return HexCode.bytes2hex(b);
    }

    /**
     * 判断文件类型
     * @param filePath 文件路径
     * @return 文件类型
     * @throws IOException IO异常
     */
    public static FileType getType(String filePath) throws IOException {
        String fileHead = getFileHeader(filePath);
        if (fileHead == null || fileHead.length() == 0) {
            return null;
        }
        fileHead = fileHead.toUpperCase();
        FileType[] fileTypes =  FileType.values();
        for (FileType type : fileTypes) {
            if (fileHead.startsWith(type.getValue())) {
                return type;
            }
        }
        return null;
    }

}
