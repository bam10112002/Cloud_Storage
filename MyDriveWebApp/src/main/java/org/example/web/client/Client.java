package org.example.web.client;

import org.apache.commons.lang3.SerializationUtils;
import org.example.Config;
import org.example.cryptography.Cryptography;
import org.example.cryptography.benaloh.Benaloh;
import org.example.cryptography.benaloh.BenalohPublicKey;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.twofish.TwoFishKey;
import org.example.cryptography.twofish.TwoFishKeyGenerator;

import org.example.web.Sender;
import org.example.web.Writer;
import org.example.web.massages.BaseMSG;
import org.example.web.massages.FileMSG;
import org.example.web.massages.FileNamesMSG;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.util.concurrent.ArrayBlockingQueue;

public class Client {
    Cryptography cryptography;
    ObjectOutputStream out;
    ObjectInputStream in;
    Socket socket;
    org.example.web.Writer writer;

    public Client(Callback collback) {
        try {
            socket = new Socket("localhost", Config.getPORT());
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            InitConnection();

            writer = new org.example.web.Writer();
            Lisener lisener = new Lisener(in, cryptography, writer, collback);
            lisener.start();


        } catch (IOException | KeyLenException | InvalidKeyException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    // Скачивание файла
    public void loadFile(String nameFileInServer, String localFileName) throws IOException {
        var msg = new BaseMSG(BaseMSG.Type.READ, nameFileInServer);
        writer.names.put(msg.getFileName(), localFileName);
        out.writeObject(cryptography.encrypt(SerializationUtils.serialize(msg)));
    }

    // Загрузка файла на сервер
    public void sendFile(String fileName) {
        new Sender(out, fileName, cryptography).start();
    }

    public void requestFileNames() throws IOException {
        out.writeObject(cryptography.encrypt(SerializationUtils.serialize(new BaseMSG(BaseMSG.Type.REQ_FILES))));
    }

    private void InitConnection() throws IOException, KeyLenException, InvalidKeyException, ClassNotFoundException {
        BenalohPublicKey publicKey = (BenalohPublicKey) in.readObject();
        System.out.println("Public key is read");
        Benaloh benaloh = new Benaloh(BigInteger.valueOf(257L));
        TwoFishKey key = (TwoFishKey) TwoFishKeyGenerator.generateKey();
        var encryptedKey = benaloh.encrypt(key.getKey(), publicKey);
        out.writeObject(encryptedKey);
        System.out.println("send encrypted two fish key");
        cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key);
    }

    private class Lisener extends Thread {
        ObjectInputStream in;
        Cryptography cryptography;
        ArrayBlockingQueue<FileMSG> queue;
        Callback collback;

        Lisener(ObjectInputStream in, Cryptography cryptography, Writer writer, Callback collback) {

            queue = writer.getQueue();
            this.in = in;
            this.cryptography = cryptography;
            this.collback = collback;
            writer.start();
        }

        @Override
        public void run() {
                while (true) {
                    BaseMSG msg;
                    try {
                        msg = SerializationUtils.deserialize(cryptography.decrypt((byte[]) in.readObject()));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                    if (msg.getType().equals(BaseMSG.Type.FILE)) {
                        queue.add((FileMSG)msg);
                        collback.LoadingCollback(((FileMSG) msg).getInd(),((FileMSG) msg).getLen(), msg.getFileName());
                    }
                    if (msg.getType().equals(BaseMSG.Type.REQ_FILES))
                        collback.FileNamesCollback(((FileNamesMSG)msg).getNames());
                }
        }
    }

    public interface Callback {
        void LoadingCollback(long curr, long len, String fileName);
        void FileNamesCollback(String [] names);
    }
}
