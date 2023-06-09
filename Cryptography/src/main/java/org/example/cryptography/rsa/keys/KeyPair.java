package org.example.cryptography.rsa.keys;

import lombok.Getter;
import org.example.cryptography.Cryptography;
import org.example.cryptography.keys.Key;

@Getter
public class KeyPair extends Key {
    byte[] publicKey;
    byte[] privateKey;
    byte[] n;

    public KeyPair(byte[] publicKey, byte[] privateKey, byte[] n) {
        super(Cryptography.Algorithm.RSA);
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.n = n;
    }
}
