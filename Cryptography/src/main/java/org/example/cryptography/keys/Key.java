package org.example.cryptography.keys;

import lombok.Data;
import org.example.cryptography.Cryptography;

@Data
public class Key {
    private Cryptography.Algorithm algorithm;
    public Key(Cryptography.Algorithm algorithm) {
        this.algorithm = algorithm;
    }
}
