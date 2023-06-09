package org.example.cryptography.benaloh;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class BenalohKeyGenerator {
    Random random = new SecureRandom();
    public BenalohKeyPair keyGeneration(int k, BigInteger R) throws InterruptedException {
        int cert = 64;
        BigInteger p, q;

        p = randomSimplisityBigInteger(R,k);
        do {
            q = new BigInteger(k, cert, random);
        } while (p.compareTo(q) == 0 || !q.subtract(BigInteger.ONE).gcd(R).equals(BigInteger.ONE));

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger y = generateY(n,phi,R);
        return new BenalohKeyPair(new BenalohPublicKey(n,y),
                new BenalohPrivateKey(phi, y.modPow(phi.divide(R),n), n));

    }

    public BigInteger generateY(BigInteger n, BigInteger phi, BigInteger R) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), random);
        } while (r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE) ||
                r.modPow(phi.divide(R), n).equals(BigInteger.ONE));

        return r;
    }

    private BigInteger randomSimplisityBigInteger(BigInteger R, int k) throws InterruptedException {
        List<BigInteger> res = Collections.synchronizedList(new ArrayList<>());
        ExecutorService executorService;

        do {
            executorService = Executors.newFixedThreadPool(20);
            for (int i = 0; i < 10; i++) {
                executorService.submit(new Check(k, res, R));
            }
            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.MINUTES);

        } while (res.isEmpty());

        return res.get(0);
    }

    private class Check implements Runnable {
        int k;
        List<BigInteger> col;
        BigInteger R;
        public Check(int k,List<BigInteger> col, BigInteger R) {
            this.k = k;
            this.col = col;
            this.R = R;
        }


        @Override
        public void run() {
            BigInteger p;
            for (int i = 0; i < 100; i++) {
                p = new BigInteger(k, 16, random);
                if (!(!p.subtract(BigInteger.ONE).divide(R).gcd(R).equals(BigInteger.ONE)
                        || p.subtract(BigInteger.ONE).mod(this.R).intValue() !=0)) {
                    col.add(p);
                }
            }
        }
    }
}
