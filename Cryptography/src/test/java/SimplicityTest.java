import org.example.cryptography.rsa.simplicityTests.*;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.util.Random;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

public class SimplicityTest {
    BigInteger[] SimplicityNumbers = {new BigInteger("13"), new BigInteger("29"), new BigInteger("7"),
            new BigInteger("1000037"), new BigInteger("1000081"), new BigInteger("1000213"),
            new BigInteger("341111111111"), new BigInteger("11213")};
    BigInteger[] Numbers = {new BigInteger("2"), new BigInteger("16"), new BigInteger("1000"),
            new BigInteger("2560"), new BigInteger("100008")};

    @Test
    void SolovayStrassenTests() throws InterruptedException {
        SimplicityTestInterface test = new SolovayStrassenTest();
        for (BigInteger num : SimplicityNumbers) {
            assertEquals(test.check(num, 0.9999),true);
        }
        for (BigInteger num : Numbers) {
            assertEquals(test.check(num, 0.9999),false);;
        }
    }

    @Test
    void FarmTests() throws InterruptedException {
        SimplicityTestInterface test = new FarmTest();
        for (BigInteger num : SimplicityNumbers) {
            assertTrue(test.check(num, 0.9999));
        }
        for (BigInteger num : Numbers) {
            assertFalse(test.check(num, 0.9999));;
        }
    }

    @Test
    void MillerRabinTests() throws InterruptedException {
        SimplicityTestInterface test = new MillerRabinTest();
        for (BigInteger num : SimplicityNumbers) {
            assertTrue(test.check(num, 0.9999));
        }
        for (BigInteger num : Numbers) {
            assertFalse(test.check(num, 0.9999));;
        }
    }

//    @Test
//    void ParallelMillerRabinTests() throws InterruptedException {
//        SimplicityTestInterface test = new MillerRabinTest();
//        SimplicityTestInterface test2 = new ParallelMillerRabinTest();
//
//        Random random = new Random();
//        for (int i = 0; i < 50; i++) {
//            BigInteger num = new BigInteger(2048, random);
//            assertEquals(test.check(num, 0.9999), test2.check(num,0.9999));
//        }
//    }
//
//    @Test
//    void TimeTest() throws InterruptedException {
//        Random random = new Random();
//        SimplicityTestInterface test = new MillerRabinTest();
//        SimplicityTestInterface test2 = new ParallelMillerRabinTest();
//        long start, end, sum1 = 0, sum2 = 0;
//
//        for (int i = 0; i < 100; i++) {
//            BigInteger num = new BigInteger(2048, random);
//            start = System.currentTimeMillis();
//            test.check(num, 0.9999);
//            end = System.currentTimeMillis();
//            sum1 += end - start;
//
//            start = System.currentTimeMillis();
//            test2.check(num, 0.9999);
//            end = System.currentTimeMillis();
//            sum2 += end - start;
//        }
//
//        System.out.println("Miller: "   + sum1);
//        System.out.println("Parallel: " + sum2);
//    }
}
