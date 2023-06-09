package org.example.cryptography;

import lombok.NonNull;
import org.example.cryptography.exceptions.XORException;

import java.nio.ByteBuffer;

public interface AlgorithmInterface {
    byte[] decrypt(byte[] data) throws XORException;
    byte[] encrypt(byte[] data) throws XORException;
    byte[] encrypt(@NonNull ByteBuffer data) throws XORException;
    byte[] decrypt(@NonNull ByteBuffer data) throws XORException;
    int getBufferSize();
}
