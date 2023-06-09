import org.example.cryptography.Cryptography;
import org.example.cryptography.des.DES;
import org.example.cryptography.exceptions.XORException;
import org.example.cryptography.keys.DESKey;
import org.example.cryptography.keys.KeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DESTest {
    @Test
    void OnlyDes() throws XORException {
        String dataString = "SOMETEXT";
        for(int i = 0; i < 100; i++) {
            var key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
            DES des = new DES(((DESKey) key).getValue());
            String decripted = new String(des.decrypt(des.encrypt(dataString.getBytes())));
            assertEquals(decripted, dataString);
        }
    }
    @ParameterizedTest
    @CsvSource({"FGTGSDRE,SAME TEXT FOR ENCRIPTION", "FGTRFWQQ,SMOLL",
            "SOME KEY, A"})
    void ECBTest(String key, String text) throws Exception {
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.ECB,
                                            new DESKey(key.getBytes()));
        String encrypted = new String(cryptography.encrypt(text.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes()));
        assertEquals(decrypted, text);
    }
    @ParameterizedTest
    @CsvSource({"FGTGSDRE,SAME TEXT FOR ENCRIPTION", "FGTRFWQQ,SMOLL",
            "SOME KEY, A"})
    void CFBTest(String key, String text) throws Exception {
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CFB,
                                                                            new DESKey(key.getBytes()));

        String encrypted = new String(cryptography.encrypt(text.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, text);
    }
    @ParameterizedTest
    @CsvSource({"FGTGSDRE,SAME TEXT FOR ENCRIPTION", "FGTRFWQQ,SMOLL",
            "SOME KEY, A"})
    void OFBTest(String key, String text) throws Exception {
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.OFB,
                                                                        new DESKey(key.getBytes()));

        String encrypted = new String(cryptography.encrypt(text.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, text);
    }

    @ParameterizedTest
    @CsvSource({"FGTGSDRE,SAME TEXT FOR ENCRIPTION", "FGTRFWQQ,SMOLL",
            "SOME KEY, A"})
    void RDTest(String key, String text) throws Exception {
        String initVector = "HJGSDURGGKMVDYQC";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.RD,
                new DESKey(key.getBytes()));

        String encrypted = new String(cryptography.encrypt(text.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, text);
    }
    @ParameterizedTest
    @CsvSource({"FGTGSDRE,SAME TEXT FOR ENCRIPTION", "FGTRFWQQ,SMOLL",
            "SOME KEY, A"})
    void CBCTest(String key, String text) throws Exception {
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CBC,
                new DESKey(key.getBytes()));

        String encrypted = new String(cryptography.encrypt(text.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, text);
    }
    @ParameterizedTest
    @CsvSource({"FGTGSDRE,SAME TEXT FOR ENCRIPTION", "FGTRFWQQ,SMOLL",
            "SOME KEY, A"})
    void CTRTest(String key, String text) throws Exception {
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CTR,
                                                                            new DESKey(key.getBytes()));

        String encrypted = new String(cryptography.encrypt(text.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, text);
    }
}
