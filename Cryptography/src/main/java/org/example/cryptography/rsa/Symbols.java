package org.example.cryptography.rsa;

import java.math.BigInteger;

public class Symbols {
    public static int legendre(BigInteger a, BigInteger p) {
        BigInteger result = a.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        if (result.equals(BigInteger.ONE)) {
            return 1;
        } else if (result.equals(BigInteger.ZERO)) {
            return 0;
        } else {
            return -1;
        }
    }
    public static int jacobi(BigInteger a, BigInteger n) {
        if (a.compareTo(BigInteger.ZERO) == 0) {
            return 0;
        } else if (a.compareTo(BigInteger.ONE) == 0) {
            return 1;
        } else {
            BigInteger two = BigInteger.valueOf(2);
            int e = 0;
            BigInteger a1 = a;
            while (a1.mod(two).compareTo(BigInteger.ZERO) == 0) {
                e++;
                a1 = a1.divide(two);
            }
            int s;
            if (e % 2 == 0 || n.mod(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(1)) == 0 || n.mod(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(7)) == 0) {
                s = 1;
            } else {
                s = -1;
            }
            if (n.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3)) == 0 && a1.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3)) == 0) {
                s = -s;
            }
            if (a1.compareTo(BigInteger.ONE) == 0) {
                return s;
            } else {
                return s * jacobi(n.mod(a1), a1);
            }
        }
    }
}
