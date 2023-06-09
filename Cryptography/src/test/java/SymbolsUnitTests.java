import org.example.cryptography.rsa.Symbols;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SymbolsUnitTests {
    @Test
    public void legendreTest() {
        int res;
        res = Symbols.legendre(new BigInteger("3453045983475934"),
                new BigInteger("2121212323231"));
        assertEquals(1, res);

        res = Symbols.legendre(new BigInteger("234235431"),
                new BigInteger("423049238741"));
        assertEquals(-1, res);

        res = Symbols.legendre(new BigInteger("40857973478576345876"),
                new BigInteger("59673457947391"));
        assertEquals(-1, res);


        res = Symbols.legendre(new BigInteger("30"),
                new BigInteger("23"));
        assertEquals(-1, res);

        res = Symbols.legendre(new BigInteger("348573459732"),
                new BigInteger("4324231"));
        assertEquals(1, res);
    }
    @Test
    public void jacobyTest() {
        int res;
        res = Symbols.jacobi(new BigInteger("3453045983475934"),
                new BigInteger("2121212323231"));
        assertEquals(1, res);

        res = Symbols.jacobi(new BigInteger("234235431"),
                new BigInteger("423049238741"));
        assertEquals(-1, res);

        res = Symbols.jacobi(new BigInteger("40857973478"),
                new BigInteger("59673451"));
        assertEquals(-1, res);


        res = Symbols.jacobi(new BigInteger("30"),
                new BigInteger("23"));
        assertEquals(-1, res);

        res = Symbols.jacobi(new BigInteger("348573459732"),
                new BigInteger("4324231"));
        assertEquals(1, res);
    }
}
