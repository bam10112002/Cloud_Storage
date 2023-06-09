package org.example.cryptography.keys;


import com.google.common.primitives.Longs;
import lombok.Getter;
import org.example.cryptography.Cryptography;

public class DESKey extends Key {
    @Getter
    private long value;
    public DESKey(byte[] key) throws Exception {
        super(Cryptography.Algorithm.DES);

        if (key.length != 8) { throw new Exception("key len must by 8 byte."); }
        value = Longs.fromByteArray(key);
    }
    public DESKey(Cryptography.Algorithm algorithm, long key) {
        super(algorithm);
        value = key;
    }
}
