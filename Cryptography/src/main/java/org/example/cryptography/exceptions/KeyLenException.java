package org.example.cryptography.exceptions;

public class KeyLenException extends Exception{
    public KeyLenException(int requiredLength, int receivedLength) {
        super("The key does not meet the standards: required length = " + requiredLength + " bit" +
                ", and received length" + receivedLength + " bit");
    }
}
