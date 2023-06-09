package org.example;

import org.example.web.client.Client;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ScrollPaneExample extends JFrame {
    JScrollPane rightPane;
    JPanel main;
    Client client;
    Map<String, JLabel> labels;

    public void setRightPane(String[] names) {
        getContentPane().remove(main);
        main.remove(rightPane);
        rightPane = initRightPanel(names);
        main.add(rightPane);
        getContentPane().add(main, BorderLayout.CENTER);
        this.setVisible(true);
    }

    public void setLabel(String fileName, String label) {
        labels.get(fileName).setText(label);
//        labels.put(fileName, labels.get(fileName).setText(label));
//        main.remove(rightPane);
//        rightPane = initRightPanel(labels.keySet().toArray(new String[0]));
//        main.add(rightPane);
//        getContentPane().add(main, BorderLayout.CENTER);
//        this.setVisible(true);
    }

    public ScrollPaneExample(Client client) {
        this.client = client;
        labels = new HashMap<>();
        main = new JPanel();
        rightPane = initRightPanel(new String[0]);
        main.setLayout(new BoxLayout(main, BoxLayout.X_AXIS));
        main.add(initLeftPanel(main, client));
        main.add(rightPane);
        getContentPane().add(main, BorderLayout.CENTER);
    }

    public JPanel initLeftPanel(JPanel root, Client client) {
//        JButton load = new JButton("Load File");
////        load.setSize(100, 50);
//        load.setMinimumSize(new Dimension(100, 50));
//        load.addActionListener(e -> {
//            String result = JOptionPane.showInputDialog(root, "Input local file name",
//                    "File Name Dialog", JOptionPane.QUESTION_MESSAGE);
//        });

        JButton sendFile = new JButton("Send File");
//        sendFile.setSize(100,50);
        sendFile.setMinimumSize(new Dimension(100, 50));
        sendFile.addActionListener(e -> {
            String result = JOptionPane.showInputDialog(root, "Input local file name",
                    "File Name Dialog", JOptionPane.QUESTION_MESSAGE);
            client.sendFile(result);
        });

        JButton requestNames = new JButton("Req File Names");
        requestNames.setMinimumSize(new Dimension(100, 50));
        requestNames.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    client.requestFileNames();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });

        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
//        leftPanel.add(load);
        leftPanel.add(requestNames);
        leftPanel.add(sendFile);

        return leftPanel;
    }

    public JScrollPane initRightPanel(String[] names) {
        // Создание панели со строковыми метками
        JPanel scroll = new JPanel();
        scroll.setLayout(new BoxLayout(scroll, BoxLayout.Y_AXIS)); // Установка вертикальной ориентации
        for (var fileNmae : names) {
            var btn = new JButton(fileNmae);
            JPanel anyFile = new JPanel();
            btn.addActionListener(e -> {
                String result = JOptionPane.showInputDialog(main, "Input local file name",
                        "Start loading file with file name: " + fileNmae, JOptionPane.INFORMATION_MESSAGE);
                try {
                    if (result != null)
                        client.loadFile(fileNmae, result);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            });
            anyFile.add(btn);
            if (!labels.containsKey(fileNmae))
                labels.put(fileNmae, new JLabel("Not loaded"));

            anyFile.add(labels.get(fileNmae));
            scroll.add(anyFile);
        }

        // Создание JScrollPane и добавление на него панели с метками
        JScrollPane scrollPane = new JScrollPane(scroll);
//        scrollPane.setMaximumSize(new Dimension(200, 400));
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setMinimumSize(new Dimension(300,500));
        return scrollPane;
    }
}
