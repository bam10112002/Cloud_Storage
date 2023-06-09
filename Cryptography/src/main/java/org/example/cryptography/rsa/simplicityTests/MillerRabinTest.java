 package org.example.cryptography.rsa.simplicityTests;

import java.math.BigInteger;

public class MillerRabinTest extends SimplicityTest {
    @Override
    public boolean check(BigInteger number, double probability) {
        // Проверяем, является ли число меньше 2 или четным
        if (number.compareTo(BigInteger.valueOf(2)) < 0 || !number.testBit(0))
            return false;

        BigInteger d = number.subtract(BigInteger.ONE);
        int s = 0;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.divide(BigInteger.TWO);
            s++;
        }

        int k = (int) Math.ceil(Math.log(1-probability)/Math.log(0.75));

        for (int i = 0; i < k; i++) {
            BigInteger a = new BigInteger(number.bitLength(), rand);
            if (a.compareTo(BigInteger.ONE) <= 0 || a.compareTo(number.subtract(BigInteger.ONE)) >= 0) {
                continue;
            }
            BigInteger x = a.modPow(d, number);
            if (x.equals(BigInteger.ONE) || x.equals(number.subtract(BigInteger.ONE))) {
                continue;
            }
            boolean prime = false;
            for (int j = 1; j < s; j++) {
                x = x.modPow(BigInteger.TWO, number);
                if (x.equals(number.subtract(BigInteger.ONE))) {
                    prime = true;
                    break;
                }
            }
            if (!prime) {
                return false;
            }
        }
        return true;
    }
}