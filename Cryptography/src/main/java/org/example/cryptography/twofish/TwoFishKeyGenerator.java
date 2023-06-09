package org.example.cryptography.twofish;

import org.example.cryptography.keys.Key;

import java.util.Random;

public class TwoFishKeyGenerator {
    public static Key generateKey() {
        Random r = new Random();
        byte[] key = new byte[16];
        r.nextBytes(key);
        return new TwoFishKey(key);
    }
}
