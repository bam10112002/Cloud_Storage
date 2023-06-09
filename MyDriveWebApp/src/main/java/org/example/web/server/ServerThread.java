package org.example.web.server;

import org.apache.commons.lang3.SerializationUtils;
import org.example.Config;
import org.example.cryptography.Cryptography;
import org.example.cryptography.benaloh.Benaloh;
import org.example.cryptography.benaloh.BenalohKeyGenerator;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.twofish.TwoFishKey;
import org.example.web.Sender;
import org.example.web.massages.BaseMSG;
import org.example.web.massages.FileMSG;
import org.example.web.massages.FileNamesMSG;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.util.concurrent.ArrayBlockingQueue;

public class ServerThread extends Thread {
    ObjectInputStream in;
    ObjectOutputStream out;
    Cryptography cryptography;
    Socket socket;
    ArrayBlockingQueue<FileMSG> queue;

    public Cryptography getCryptography() {
        return cryptography;
    }

    ServerThread(Socket socket, ArrayBlockingQueue<FileMSG> queue) throws IOException {
        this.socket = socket;
        this.queue = queue;
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
    }

    @Override
    public void run() {
        initConnection();
        try {
            while (true) {
                BaseMSG msg = SerializationUtils.deserialize(cryptography.decrypt((byte[]) in.readObject()));
                switch (msg.getType()) {
                    case FILE -> queue.add((FileMSG) msg);
                    case READ -> new Sender(out, msg.getFileName(), cryptography).start();
                    case CLOSE_CONNECTION -> {
                        return;
                    }
                    case REQ_FILES -> {
                        var newMsg = new FileNamesMSG(new File(Config.getRESOURSEDIR()).list());
                        out.writeObject(cryptography.encrypt(SerializationUtils.serialize(newMsg)));
                    }
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            System.err.println(e.getMessage());
        }
    }

    public boolean initConnection(){
        try {
            System.out.println("[LOG] Client Conected");
            Benaloh benaloh = new Benaloh(BigInteger.valueOf(257L));
            BenalohKeyGenerator benalohKeyGenerator = new BenalohKeyGenerator();
            var keys = benalohKeyGenerator.keyGeneration(256, BigInteger.valueOf(257L));
            out.writeObject(keys.getPublicKey());

            byte[][] encryptedTwoFishKey = (byte[][]) in.readObject();
            TwoFishKey key = new TwoFishKey(benaloh.decrypt(encryptedTwoFishKey, keys.getPrivateKey()));
            cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key);
            System.out.println("[LOG] Initial ended");
            return true;
        }
        catch (InterruptedException | IOException | ClassNotFoundException | KeyLenException | InvalidKeyException e) {
            return false;
        }
    }
}
