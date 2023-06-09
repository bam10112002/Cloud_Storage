package org.example.cryptography.exceptions;

public class XORException extends Exception {
    public XORException(int firstLen, int secondLen) {
        super("BitSet sizes don't match, first = " + firstLen + ", second = " + secondLen + "");
    }
}
