package org.example.cryptography.rsa;

import lombok.NonNull;
import org.example.cryptography.AlgorithmInterface;
import org.example.cryptography.exceptions.XORException;
import org.example.cryptography.rsa.keys.KeyPair;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class RSA implements AlgorithmInterface {
    KeyPair pair;
    public RSA(KeyPair keys) {
        this.pair = keys;
    }

    public int GetKeyLen() {
        return pair.getN().length;
    }

//    public byte[] encript(byte[] data) {
//        if (data.length > pair.getPublicKey().length)
//            return new byte[0];
//
//        new BigInteger(pair.getPublicKey());
//        return new BigInteger(data).modPow(new BigInteger(pair.getPublicKey()),
//                new BigInteger(pair.getN())).toByteArray();
//    }
//
//    public byte[] decript(byte[] data) {
//        if (data.length > pair.getPublicKey().length)
//            return new byte[0];
//
//        new BigInteger(pair.getPublicKey());
//        return new BigInteger(data).modPow(new BigInteger(pair.getPrivateKey()),
//                new BigInteger(pair.getN())).toByteArray();
//    }

    @Override
    public byte[] decrypt(byte[] data) throws XORException {
        if (data.length > pair.getN().length)
            return new byte[0];

        new BigInteger(pair.getPublicKey());
        return new BigInteger(data).modPow(new BigInteger(pair.getPrivateKey()),
                new BigInteger(pair.getN())).toByteArray();
    }

    @Override
    public byte[] encrypt(byte[] data) throws XORException {
        if (data.length > pair.getN().length)
            return new byte[0];

        new BigInteger(pair.getPublicKey());
        return new BigInteger(data).modPow(new BigInteger(pair.getPublicKey()),
                new BigInteger(pair.getN())).toByteArray();
    }

    @Override
    public byte[] encrypt(@NonNull ByteBuffer data) throws XORException {
        var dataArr = data.array();
        if (dataArr.length > pair.getN().length)
            return new byte[0];

        new BigInteger(pair.getPublicKey());
        return new BigInteger(dataArr).modPow(new BigInteger(pair.getPublicKey()),
                new BigInteger(pair.getN())).toByteArray();
    }

    @Override
    public byte[] decrypt(@NonNull ByteBuffer data) throws XORException {
        var dataArr = data.array();
        if (dataArr.length > pair.getN().length)
            return new byte[0];

        new BigInteger(pair.getPublicKey());
        return new BigInteger(dataArr).modPow(new BigInteger(pair.getPrivateKey()),
                new BigInteger(pair.getN())).toByteArray();
    }

    @Override
    public int getBufferSize() {
        return 0;
    }
}
