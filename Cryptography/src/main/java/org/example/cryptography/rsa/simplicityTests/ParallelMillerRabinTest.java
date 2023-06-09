package org.example.cryptography.rsa.simplicityTests;

import lombok.AllArgsConstructor;

import java.math.BigInteger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

// Не дал прироста в скорости, не рекомендуется к использованию
@Deprecated
public class ParallelMillerRabinTest extends SimplicityTest {
    @Override
    public boolean check(BigInteger number, double probability) throws InterruptedException {
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
        ExecutorService executorService = Executors.newFixedThreadPool(k);
        AtomicBoolean simlicity = new AtomicBoolean(true);

        for (int i = 0; i < k; i++) {
            executorService.execute(new Check(number, d, s, simlicity));
        }
        executorService.shutdown();
        executorService.awaitTermination(10, TimeUnit.MINUTES);
        return simlicity.get();
    }

    @AllArgsConstructor
    private class Check implements Runnable {
        BigInteger number, d;
        int s;
        AtomicBoolean simlicity;

        @Override
        public void run() {
            BigInteger a = new BigInteger(number.bitLength(), rand);

            if (a.compareTo(BigInteger.ONE) <= 0 || a.compareTo(number.subtract(BigInteger.ONE)) >= 0) {
                return;
            }
            BigInteger x = a.modPow(d, number);
            if (x.equals(BigInteger.ONE) || x.equals(number.subtract(BigInteger.ONE))) {
                return;
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
                simlicity.set(false);
            }
        }
    }
}
