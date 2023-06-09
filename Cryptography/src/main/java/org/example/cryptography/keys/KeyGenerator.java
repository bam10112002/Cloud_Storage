package org.example.cryptography.keys;

import lombok.NonNull;
import org.example.cryptography.Cryptography;

import java.util.Random;

public class KeyGenerator {
    static Random rand = new Random();
    public static @NonNull Key generateKey(@NonNull Cryptography.Algorithm algorithm) {
        switch (algorithm){
            case DES:
                return (Key) new DESKey(algorithm, rand.nextLong()/2);
            default:
                throw new IllegalStateException("Unexpected value: " + algorithm);
        }
    }
}
