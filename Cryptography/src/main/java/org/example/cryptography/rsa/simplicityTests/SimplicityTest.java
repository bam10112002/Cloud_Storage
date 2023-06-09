package org.example.cryptography.rsa.simplicityTests;

import lombok.NonNull;

import java.math.BigInteger;
import java.util.Random;

public abstract class SimplicityTest implements SimplicityTestInterface {
    protected static final Random rand = new Random();

    protected static @NonNull BigInteger randomBigInteger(@NonNull BigInteger min, @NonNull BigInteger max) {
        BigInteger result;
        do {
            result = new BigInteger(max.bitLength(), rand);
        } while (result.compareTo(min) < 0 || result.compareTo(max) > 0);
        return result;
    }

    public static BigInteger modPow(BigInteger a, BigInteger b, BigInteger mod){
        BigInteger res = BigInteger.ONE;
        BigInteger two = BigInteger.valueOf(2);

        int len = res.bitLength();
        for (int i = len-1; i >= 0; i--) {
            if (b.testBit(i))
                res = res.multiply(a);

            res = res.modPow(two, mod);
        }
        return res;
    }
}
