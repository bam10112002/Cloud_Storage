package org.example.cryptography.benaloh;

import java.math.BigInteger;

public class BenalohPrivateKey {
    private final BigInteger x;
    private final BigInteger phi;
    private final BigInteger n;

    public BenalohPrivateKey(BigInteger phi, BigInteger x, BigInteger n) {
        this.phi = phi;
        this.x = x;
        this.n = n;
    }
    public BigInteger getPhi() {
        return phi;
    }
    public BigInteger getX() {
        return x;
    }

    public BigInteger getN() {
        return n;
    }
}
