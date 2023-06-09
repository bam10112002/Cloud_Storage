import org.example.cryptography.Cryptography;
import org.example.cryptography.benaloh.Benaloh;
import org.example.cryptography.benaloh.BenalohKeyGenerator;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.twofish.TwoFish;
import org.example.cryptography.twofish.TwoFishKey;
import org.example.cryptography.twofish.TwoFishKeyGenerator;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class NetTest {
    @Test
    void Test1() throws InvalidKeyException, InterruptedException, KeyLenException {
        // user1
        Benaloh benaloh = new Benaloh(BigInteger.valueOf(257L));
        BenalohKeyGenerator benalohKeyGenerator = new BenalohKeyGenerator();
        var keys = benalohKeyGenerator.keyGeneration(20, BigInteger.valueOf(257L));
        // передача публичного ключа другому пользователю

        // user2
        TwoFishKey key1 = (TwoFishKey) TwoFishKeyGenerator.generateKey();
        var encriptedKey = benaloh.encrypt(key1.getKey(), keys.getPublicKey());

        // передача зашифрованного ключа симметричного шифрования

        //user1
        var decriptedKey = benaloh.decrypt(encriptedKey, keys.getPrivateKey());
        TwoFishKey key2 = new TwoFishKey(decriptedKey);

        // на данном оба пользователя имеют ключ для симметричного шифрования

        // базовая проверка работоспособности
        String data = "Hello world";
        Cryptography cryptography1 = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key1);
        Cryptography cryptography2 = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key2);
        String newData = new String(cryptography1.decrypt(cryptography2.encrypt(data.getBytes())));
        assertEquals(data, newData);
    }
}
