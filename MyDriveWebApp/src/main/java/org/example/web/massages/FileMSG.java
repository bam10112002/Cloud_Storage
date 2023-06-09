package org.example.web.massages;

public class FileMSG extends BaseMSG {
    private byte[] data;
    private long ind;
    private long len;

    public FileMSG(Type tp, String fileName, byte[] data, long ind, long len) {
        super(tp, fileName);
        this.data = data;
        this.ind = ind;
        this.len = len;
    }

    public long getInd() {
        return ind;
    }

    public long getLen() {
        return len;
    }

    public byte[] getData() {
        return data;
    }
}
