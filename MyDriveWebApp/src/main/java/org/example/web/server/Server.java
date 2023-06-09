package org.example.web.server;

import org.example.Config;
import org.example.web.Writer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public Server() throws IOException, ClassNotFoundException {
        ServerSocket serverSocket = new ServerSocket(Config.getPORT());

        Writer writer = new Writer();
        var queue = writer.getQueue();
        writer.start();

        System.out.println("[LOG] Server started");
        while (!serverSocket.isClosed()) {
            Socket client = serverSocket.accept();
            new ServerThread(client, queue).start();
        }
    }
}
