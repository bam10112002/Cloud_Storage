import org.example.cryptography.exceptions.XORException;
import org.example.cryptography.rsa.RSA;
import org.example.cryptography.rsa.keys.KeyPair;
import org.example.cryptography.rsa.keys.ParallelRSAKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RSATest {
    @Test
    void Test1() throws InterruptedException, XORException {
        String data = "Hello my name is Artem";
        var gen = new ParallelRSAKeyGenerator();
        KeyPair keys = gen.generateKeyPair(1024);
        RSA rsa = new RSA(keys);
        byte[] encripted = rsa.encrypt(data.getBytes());
        String decripted = new String(rsa.decrypt(encripted));
        assertEquals(data, decripted);
    }

}
