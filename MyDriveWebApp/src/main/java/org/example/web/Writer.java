package org.example.web;

import org.example.Config;
import org.example.web.massages.FileMSG;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

public class Writer extends Thread {
    ArrayBlockingQueue<FileMSG> queue;
    Map<String, FileOutputStream> streams;
    public Map<String, String> names;

    public Writer() {
        queue = new ArrayBlockingQueue<>(5000);
        streams = new HashMap<>();
        names = new HashMap<>();
    }

    public ArrayBlockingQueue<FileMSG> getQueue() {
        return queue;
    }

    @Override
    public void run() {
        super.run();

        while (true) {
            try {
                var msg = queue.take();
                var stream = streams.getOrDefault(msg.getFileName(), null);
                var name = names.getOrDefault(msg.getFileName(), msg.getFileName());

                if (stream == null) {
                    stream = new FileOutputStream(Config.getRESOURSEDIR() + name);
                    streams.put(msg.getFileName(), stream);
                }
                stream.write(msg.getData());

                if (msg.getInd() == msg.getLen())
                    streams.remove(msg.getFileName());


            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
