package org.example.cryptography.twofish;

import org.example.cryptography.Cryptography;
import org.example.cryptography.keys.Key;

public class TwoFishKey extends Key {
    byte[] key;

    public TwoFishKey(byte[] key) {
        super(Cryptography.Algorithm.TWOFISH);
        this.key = key;
    }

    public byte[] getKey() {
        return key;
    }
}
