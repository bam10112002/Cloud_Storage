package org.example.web;

import org.apache.commons.lang3.SerializationUtils;
import org.example.Config;
import org.example.cryptography.Cryptography;
import org.example.web.massages.BaseMSG;
import org.example.web.massages.FileMSG;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class Sender extends Thread {
    ObjectOutputStream out;
    String filename;
    Cryptography cryptography;

    public Sender(ObjectOutputStream out, String filename, Cryptography cryptography) {
        this.out = out;
        this.filename = filename;
        this.cryptography = cryptography;
    }

    @Override
    public void run() {
        super.run();
        File file = new File(Config.getRESOURSEDIR() + filename);
        int len = (int)Math.ceil(file.length()*1.0/Config.getBLOCKSIZE());
        try (FileInputStream stream = new FileInputStream(file)) {
            for (int i = 0; i < len; i++) {
                var arr = stream.readNBytes(Config.getBLOCKSIZE());
                var msg = new FileMSG(BaseMSG.Type.FILE, filename, arr, i+1, len);
                out.writeObject(cryptography.encrypt(SerializationUtils.serialize(msg)));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
