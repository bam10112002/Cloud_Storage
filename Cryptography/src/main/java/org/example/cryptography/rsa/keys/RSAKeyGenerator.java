package org.example.cryptography.rsa.keys;

import lombok.NonNull;
import org.example.cryptography.rsa.simplicityTests.MillerRabinTest;
import org.example.cryptography.rsa.simplicityTests.ParallelMillerRabinTest;
import org.example.cryptography.rsa.simplicityTests.SimplicityTest;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class RSAKeyGenerator {
    private static final Random rand = new Random();
    private static final SimplicityTest test = new MillerRabinTest();

    public @NonNull KeyPair generateKeyPair(int keyLen) throws InterruptedException {
        BigInteger max = getMax(keyLen);
        BigInteger p = randomSimplisityBigInteger(BigInteger.valueOf(0L), max);
        BigInteger q = randomSimplisityBigInteger(BigInteger.valueOf(0L), max);
        BigInteger phi = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        BigInteger e = randomBigInteger(BigInteger.valueOf(0L).setBit(keyLen), phi);
        while (hasCommonDivisors(phi, e)) {
            e = randomBigInteger(BigInteger.valueOf(0L).setBit(keyLen), phi);
        }
        BigInteger d = e.modInverse(phi);

        return new KeyPair(e.toByteArray(), d.toByteArray(), p.multiply(q).toByteArray());
    }

    private static @NonNull BigInteger randomBigInteger(@NonNull BigInteger min, @NonNull BigInteger max) {
        BigInteger result;
        do {
            result = new BigInteger(max.bitLength(), rand);
        } while (result.compareTo(min) < 0 || result.compareTo(max) > 0);

        return result;
    }

    private @NonNull BigInteger randomSimplisityBigInteger(@NonNull BigInteger min, @NonNull BigInteger max) throws InterruptedException {
        BigInteger result;

        do {
            result = new BigInteger(max.bitLength(), rand);
        } while (!test.check(result, 0.9999));

        return result;
    }

    private static BigInteger getMax(int len) {
        BigInteger bigInt = BigInteger.valueOf(0L);
        bigInt = bigInt.setBit(len);
        for (int i = 0; i < len; i++) {
            bigInt = bigInt.setBit(i);
        }
        return bigInt;
    }

    /**
     * Находит наибольший общий делитель
     *
     * @param a первое число
     * @param b второе число
     * @return наибольший общий делитель
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger t = b;
            b = a.mod(b);
            a = t;
        }
        return a.abs();
    }

    /**
     * Проверяет, имеют ли два числа общие делители
     *
     * @param a первое число
     * @param b второе число
     * @return true, если числа имеют общие делители, false в обратном случае
     */
    public static boolean hasCommonDivisors(BigInteger a, BigInteger b) {
        BigInteger gcd = gcd(a, b);
        return !gcd.equals(BigInteger.ONE);
    }

    private class Check implements Runnable {
        BigInteger num;
        List<BigInteger> col;

        public Check(BigInteger num,List<BigInteger> col) {
            this.num = num;
            this.col = col;
        }


        @Override
        public void run() {
            try {
                if (test.check(num, 0.9999)) {
                    col.add(num);
                }
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

    }
}
