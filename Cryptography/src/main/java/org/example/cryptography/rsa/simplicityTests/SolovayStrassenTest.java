package org.example.cryptography.rsa.simplicityTests;

import lombok.NonNull;
import org.example.cryptography.rsa.Symbols;

import java.math.BigInteger;

public class SolovayStrassenTest extends SimplicityTest{
    @Override
    public boolean check(BigInteger number, double probability) {
        // Проверяем, является ли число меньше 2 или четным
        if (number.compareTo(BigInteger.valueOf(2)) < 0 || !number.testBit(0))
            return false;

        // Количество итераций для вероятностного теста
        int iterations = (int) Math.ceil(Math.log(1-probability)/Math.log(0.5));

        // Генерируем случайные числа и проверяем на простоту
        for (int i = 0; i < iterations; i++) {
            BigInteger a = randomBigInteger(BigInteger.ONE, number.subtract(BigInteger.ONE));
            BigInteger j = a.modPow(number.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), number);
            BigInteger J = BigInteger.valueOf(Symbols.jacobi(a, number));
            if (!j.equals(J)) {
                return true;
            }
        }
        return false;
    }
}
