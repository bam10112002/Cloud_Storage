package org.example;

import org.example.web.client.Client;

import javax.swing.*;

public class MyCallback implements Client.Callback {
    ScrollPaneExample panel;

    public void setPanel(ScrollPaneExample panel) {
        this.panel = panel;
    }

    @Override
    public void LoadingCollback(long l, long l1, String s) {
        if (l != l1)
            panel.setLabel(s, l + "/" + l1);
        else
            panel.setLabel(s, "loaded");
        panel.repaint();
    }

    @Override
    public void FileNamesCollback(String[] strings) {
        panel.setRightPane(strings);
        panel.repaint();
    }
}