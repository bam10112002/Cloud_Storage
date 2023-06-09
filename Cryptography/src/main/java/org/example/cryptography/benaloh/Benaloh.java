package org.example.cryptography.benaloh;

import lombok.NonNull;
import org.example.cryptography.AlgorithmInterface;
import org.example.cryptography.exceptions.XORException;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;

public class Benaloh {

    Random random = new SecureRandom();
    public BigInteger R;

    public Benaloh(BigInteger R) {
        this.R = R;
    }

    private BigInteger randomNumFromZ(BigInteger n) {
        BigInteger num;
        do {
            num = new BigInteger(n.bitLength(), random);
        } while (num.compareTo(n) >= 0 || !num.gcd(n).equals(BigInteger.ONE));
        return num;
    }

    public BigInteger encrypt(BigInteger data, BenalohPublicKey publicKey){
        BigInteger u = randomNumFromZ(publicKey.getN());
        BigInteger cipher1 = publicKey.getY().modPow(data, publicKey.getN());
        BigInteger cipher2 = u.modPow(this.R, publicKey.getN());

        return cipher1.multiply(cipher2).mod(publicKey.getN());
    }

    public BigInteger decrypt(BigInteger data, BenalohPrivateKey privateKey){
        BigInteger a = data.modPow(privateKey.getPhi().divide(this.R), privateKey.getN());

        BigInteger c;
        for(BigInteger i=BigInteger.ZERO; i.compareTo(R) < 0; i = i.add(BigInteger.ONE)) {
            c = privateKey.getX().modPow(i, privateKey.getN());
            if(a.equals(c))
                return i;
        }
        return BigInteger.valueOf(-1);
    }

    public byte[][] encrypt(byte[] data, BenalohPublicKey publicKey) {
        byte[][] res = new byte[data.length][];
        for (int i = 0 ; i < data.length; i++) {
            res[i] = encrypt(BigInteger.valueOf(data[i] & 0xFF), publicKey).toByteArray();
        }
        return res;
    }
    public byte[] decrypt(byte[][] data, BenalohPrivateKey privateKey) {
        byte[] res = new byte[data.length];
        for (int i = 0 ; i < data.length; i++) {
            res[i] = (byte)decrypt(new BigInteger(data[i]), privateKey).intValue();
        }
        return res;
    }
}