package com.ggp.noob.util;

import com.alibaba.fastjson.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

/**
 * @Author:ggp
 * @Date:2020-05-07 16:09
 * @Description:
 */
public class FileUtil {
    private static Logger logger = LoggerFactory.getLogger(FileUtil.class);

    /**
     * 从文件中读取json并转化为对象
     *
     * @param filePath
     * @param clazz
     * @return
     */
    public static Object readJsonObjectFromFile(String filePath, Class clazz) throws Exception {
        String jsonString = readStringFromFile(filePath);
        return JSON.parseObject(jsonString, clazz);
    }

    /**
     * 从文件中读取字符串
     *
     * @param filePath
     * @return
     * @throws Exception
     */
    public static String readStringFromFile(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) {
            logger.error("文件不存在");
            throw new FileNotFoundException();
        }
        StringBuilder content = new StringBuilder();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            String temp;
            while (null != (temp = reader.readLine())) {
                content.append(temp);
            }
            return content.toString();
        } catch (Exception e) {
            logger.error("从文件读取字符串异常", e);
        } finally {
            if (null != reader) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    logger.error("关闭流异常", e);
                }
            }
        }
        return null;
    }

    /**
     * 往文件中写入字符串
     *
     * @param filePath
     * @param content
     * @throws Exception
     */
    public static void writeStringToFile(String filePath, String content) {
        File file = new File(filePath);
        FileWriter writer = null;
        try {
            if (file.exists()) {
                file.delete();
            }
            file.getParentFile().mkdirs();
            file.createNewFile();
            writer = new FileWriter(file);
            if (null != content) {
                writer.write(content);
            }
            writer.flush();
        } catch (Exception e) {
            logger.error("写入文件失败", e);
        } finally {
            if (null != writer) {
                try {
                    writer.close();
                } catch (IOException e) {
                    logger.error("关闭流异常", e);
                }
            }
        }
    }

    /**
     * 往文件写入字节数组
     *
     * @param path
     * @param bytes
     */
    public static void writeBytesToFile(String path, byte[] bytes) {
        File file = new File(path);
        BufferedOutputStream bos = null;
        try {
            if (file.exists()) {
                file.delete();
            }
            file.getParentFile().mkdirs();
            file.createNewFile();
            bos = new BufferedOutputStream(new FileOutputStream(file));
            bos.write(bytes);
            bos.flush();
        } catch (Exception e) {
            logger.error("写入文件失败", e);
        } finally {
            if (null != bos) {
                try {
                    bos.close();
                } catch (IOException e) {
                    logger.error("关闭流异常", e);
                }
            }
        }
    }

    /**
     * 从文件中读字节数组
     *
     * @param path
     * @return
     * @throws Exception
     */
    public static byte[] readBytesFromFile(String path) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            logger.error("文件不存在");
            throw new FileNotFoundException();
        }
        BufferedInputStream bis = null;
        int offset = 0;
        byte[] buffer = null;
        try {
            long size = file.length();
            buffer = new byte[(int) size];
            bis = new BufferedInputStream(new FileInputStream(file));
            int number = 0;
            while (offset < file.length() && (number = bis.read(buffer, offset, buffer.length - offset)) > 0) {
                offset += number;
            }
        } catch (Exception e) {
            logger.error("读取文件失败", e);
        } finally {
            if (null != bis) {
                bis.close();
            }
        }
        if (offset != file.length()) {
            throw new RuntimeException("file not read complete!");
        }
        return buffer;
    }

    /**
     * 删除目录（文件夹）以及目录下的文件
     *
     * @param sPath 被删除目录的文件路径
     * @return 目录删除成功返回true，否则返回false
     */
    public static boolean deleteDirectory(String sPath) {
        //如果sPath不以文件分隔符结尾，自动添加文件分隔符
        if (!sPath.endsWith(File.separator)) {
            sPath = sPath + File.separator;
        }
        File dirFile = new File(sPath);
        //如果dir对应的文件不存在，或者不是一个目录，则退出
        if (!dirFile.exists() || !dirFile.isDirectory()) {
            return false;
        }
        boolean flag = true;
        //删除文件夹下的所有文件(包括子目录)
        File[] files = dirFile.listFiles();
        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                //删除子文件
                if (files[i].isFile()) {
                    flag = deleteFile(files[i].getAbsolutePath());
                    if (!flag) {
                        break;
                    }
                } //删除子目录
                else {
                    flag = deleteDirectory(files[i].getAbsolutePath());
                    if (!flag) {
                        break;
                    }
                }
            }
        }
        if (!flag) {
            return false;
        }
        //删除当前目录
        return dirFile.delete();
    }

    /**
     * 删除文件
     *
     * @param sPath 被删除的文件路径
     * @return 目录删除成功返回true，否则返回false
     */
    public static boolean deleteFile(String sPath) {
        Path path = Paths.get(sPath);
        try {
            return Files.deleteIfExists(path);
        } catch (IOException e) {
            logger.error("delete dir error", e);
            return false;
        }
    }

    /**
     * 写入properties（store方法会对某些字符转义）
     *
     * @param properties 配置文件
     * @param filePath   文件路径
     * @throws Exception
     */
    public static void writeProperties(Properties properties, String filePath) throws Exception {
        OutputStream os = new FileOutputStream(filePath);
        Enumeration<?> e = properties.propertyNames();
        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            String line = key + "=" + properties.getProperty(key) + System.getProperty("line.separator");
            os.write(line.getBytes());
        }
        os.flush();
    }

    /**
     * 读取文本文件到字符串
     *
     * @param inputStream 文件输入流
     * @return 读取结果
     * @throws IOException 读取异常
     */
    public static String readFile(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder buff = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            buff.append(line);
        }
        return buff.toString();
    }

    /**
     * 从文件中读取行数据
     *
     * @param filePath
     * @return
     */
    public static List<String> readLines(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException();
        }
        List<String> list = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String temp;
        while (null != (temp = reader.readLine())) {
            list.add(temp);
        }
        return list;
    }

    }
