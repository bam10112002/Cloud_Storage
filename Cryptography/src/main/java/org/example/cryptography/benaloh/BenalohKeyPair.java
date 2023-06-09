package org.example.cryptography.benaloh;

public class BenalohKeyPair {
    BenalohPublicKey publicKey;
    BenalohPrivateKey privateKey;

    public BenalohKeyPair(BenalohPublicKey publicKey, BenalohPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public BenalohPublicKey getPublicKey() {
        return publicKey;
    }

    public BenalohPrivateKey getPrivateKey() {
        return privateKey;
    }
}
