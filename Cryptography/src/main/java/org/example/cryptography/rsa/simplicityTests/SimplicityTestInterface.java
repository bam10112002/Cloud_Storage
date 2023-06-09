package org.example.cryptography.rsa.simplicityTests;

import lombok.NonNull;

import java.math.BigInteger;
import java.util.Random;

public interface SimplicityTestInterface {
    boolean check(@NonNull BigInteger number, double probability) throws InterruptedException;
}
