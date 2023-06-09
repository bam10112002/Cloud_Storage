package org.example;
import org.example.web.client.Client;


import java.io.*;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Collectors;

public class ClientApp {

    public static void main(String[] args) throws IOException {
//        Client client = new Client(new MyCollback());
//        client.loadFile("book.txt", "dlkjg");
//        client.loadFile("text.txt", "name2");
//        Scanner scanner = new Scanner(System.in);
//        String str;
//        while (true) {
//            System.out.println("send/load/names");
//            str = scanner.nextLine();
//            switch (str) {
//                case "send" : {
//                    String name = scanner.nextLine();
//                    client.sendFile(name);
//                }
//                case "load" : {
//                    System.out.println("Input serverName/localName");
//                    String name = scanner.nextLine();
//                    String name2 = scanner.nextLine();
//                    client.loadFile(name, name2);
//                }
//                case "names" : {
//                    client.requestFileNames();
//                }
//            }
//
//        }
    }
}

class MyCollback implements Client.Callback {
    @Override
    public void LoadingCollback(long curr, long len, String fileName) {
        System.out.println(fileName + "loading:" + curr + "/" + len);
        if (curr == len )
            System.out.println(fileName + " saved");
    }

    @Override
    public void FileNamesCollback(String[] names) {
        System.out.print("Available files: ");
        System.out.println(Arrays.stream(names).collect(Collectors.joining(", ")));
    }
}