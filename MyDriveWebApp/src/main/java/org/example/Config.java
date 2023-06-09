package org.example;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Config {
    static int BLOCKSIZE;
    static int PORT;
    static String RESOURSEDIR;

    static {
        try {
            Properties props = new Properties();
            props.load(new FileInputStream(new File("src/main/resources/application.properties")));
            RESOURSEDIR = props.getProperty("resources_dir");
            BLOCKSIZE = Integer.parseInt(props.getProperty("block_size"));
            PORT = Integer.parseInt(props.getProperty("port"));

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static int getPORT() {
        return PORT;
    }

    public static int getBLOCKSIZE() {
        return BLOCKSIZE;
    }

    public static String getRESOURSEDIR() {
        return RESOURSEDIR;
    }
}
