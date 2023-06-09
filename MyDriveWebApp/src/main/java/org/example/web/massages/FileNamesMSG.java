package org.example.web.massages;

public class FileNamesMSG extends BaseMSG{
    String[] names;

    public String[] getNames() {
        return names;
    }

    public FileNamesMSG(String[] names) {
        super(Type.REQ_FILES);
        this.names = names;
    }
}
