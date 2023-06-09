package org.example.cryptography.rsa.simplicityTests;

import lombok.NonNull;

import java.math.BigInteger;

public class FarmTest extends SimplicityTest {

    @Override
    public boolean check(BigInteger number, double probability) {
        if (number.compareTo(BigInteger.valueOf(2)) < 0 || !number.testBit(0))
            return false;

        int iterations = (int) Math.ceil(Math.log(1-probability)/Math.log(0.5));
        for (int i = 0; i < iterations; i++) {
            BigInteger a = randomBigInteger(BigInteger.ONE, number.subtract(BigInteger.ONE));
            if (!a.modPow(number.subtract(BigInteger.ONE), number).equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }
}
