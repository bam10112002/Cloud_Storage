package org.example;

import org.example.web.client.Client;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        // Создание и отображение окна
        MyCallback callback = new MyCallback();
        Client client = new Client(callback);

        ScrollPaneExample frame = new ScrollPaneExample(client);
        callback.setPanel(frame);

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 400);
        frame.setVisible(true);
    }
}
