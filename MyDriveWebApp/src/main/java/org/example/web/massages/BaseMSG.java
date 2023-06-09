package org.example.web.massages;

import java.io.Serializable;

public class BaseMSG implements Serializable {
    public enum Type {FILE, READ, CLOSE_CONNECTION, REQ_FILES}
    private Type type;
    private String fileName;

    public Type getType() {
        return type;
    }

    public String getFileName() {
        return fileName;
    }

    public BaseMSG(Type tp) {
        type = tp;
        fileName = "";
    }
    public BaseMSG(Type tp, String fileName) {
        type = tp;
        this.fileName = fileName;
    }
}
