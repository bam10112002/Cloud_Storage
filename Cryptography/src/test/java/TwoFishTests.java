import org.example.cryptography.Cryptography;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.keys.Key;
import org.example.cryptography.twofish.TwoFish;
import org.example.cryptography.twofish.TwoFishKey;
import org.example.cryptography.twofish.TwoFishKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.script.ScriptContext;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TwoFishTests {

    @ParameterizedTest
    @ValueSource(strings = {"Hello World"})
    void Test1(String scannerInput) throws InvalidKeyException {
//        Scanner sc = new Scanner(System.in);// Scanner to accept user input

//        System.out.println("Plain text (input): ");

//        String scannerInput = sc.nextLine();
//        sc.close();

        // Convert input String to byte array
        byte[] normalizedData = scannerInput.getBytes();

        // Initialize ArrayList: Used to handle input size (should multiple of 8
        ArrayList<Byte> inputText = new ArrayList();

        // If input text is less than 128 bits
        if(normalizedData.length > 16) {
            // Add all p elements in arraylist
            for(int i = 0; i<normalizedData.length;i++) {
                inputText.add(normalizedData[i]);
            }

            // Increment array list size until it reaches a multiple of 8 (bytes)
            // and populate missing elements with 0 bytes
            while(inputText.size() % 8 != 0){
                inputText.add((byte)0);
            }

            // Create new Array that would be used as input to blockEncrypt
            normalizedData = null;
            normalizedData = new byte[inputText.size()];
            for(int i=0; i<normalizedData.length; i++) {
                normalizedData[i] = inputText.get(i);
            }
        }

        // If p length is less than 128 bits
        else if(normalizedData.length <= 16) {

            // First copy all p elements to array list
            for(int i=0; i < normalizedData.length; i++) {
                inputText.add(normalizedData[i]);
            }

            // Fill in the missing elements with 0
            for(int i = inputText.size();i<16; i++) {
                inputText.add((byte)0);
            }

            // Recreate byte array from the array list (input to blockEncrypt)
            normalizedData = null;
            normalizedData = new byte[inputText.size()];
            for(int i=0; i<normalizedData.length; i++) {
                normalizedData[i] = inputText.get(i);
            }
        }
        System.out.println("Input Text : ");
        System.out.println(new String(normalizedData));


        Random r = new Random();
        byte[] key = new byte[16];
        r.nextBytes(key);

        TwoFish twoFish = new TwoFish(new TwoFishKey(key));


        ArrayList<byte[]> ciphers = new ArrayList();

        byte[] cipher;

        for(int i = 0 ; i < inputText.size() / 16; i++) {
//            cipher = twoFish.blockEncrypt(normalizedData,  16 * i);
            cipher = twoFish.encrypt(normalizedData);
            ciphers.add(cipher);
        }


        System.out.println("Decrypted Cipher Text : ");

        for(int i = 0; i < ciphers.size(); i++) {
            byte[] decrypted =  twoFish.decrypt(ciphers.get(i));
//            byte[] decrypted =  twoFish.blockDecrypt(ciphers.get(i),0);
            String decryptedString = new String(decrypted);
            System.out.print(decryptedString);
        }
        System.out.println("\n");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Hello world", "12345678901234567890", "some large text to test normalize and denormalize data"})
    void ECBTests(String data) throws InvalidKeyException, KeyLenException {
        var key = TwoFishKeyGenerator.generateKey();
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key);
        byte[] encripted = cryptography.encrypt(data.getBytes());
        byte[] decripted = cryptography.decrypt(encripted);
        assertEquals(data, new String(decripted));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Hello world", "12345678901234567890", "some large text to test normalize and denormalize data"})
    void CTRTests(String data) throws InvalidKeyException, KeyLenException {
        String initVector = "HJGSDURGHJGSDURG";
        var key = TwoFishKeyGenerator.generateKey();
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.CTR, key);
        byte[] encripted = cryptography.encrypt(data.getBytes(), initVector.getBytes());
        byte[] decripted = cryptography.decrypt(encripted, initVector.getBytes());
        assertEquals(data, new String(decripted));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Hello world", "12345678901234567890", "some large text to test normalize and denormalize data"})
    void CBCTests(String data) throws InvalidKeyException, KeyLenException {
        String initVector = "HJGSDURGHJGSDURG";
        var key = TwoFishKeyGenerator.generateKey();
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.CBC, key);
        byte[] encripted = cryptography.encrypt(data.getBytes(), initVector.getBytes());
        byte[] decripted = cryptography.decrypt(encripted, initVector.getBytes());
        assertEquals(data, new String(decripted));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Hello world", "12345678901234567890", "some large text to test normalize and denormalize data"})
    void CFBTests(String data) throws InvalidKeyException, KeyLenException {
        String initVector = "HJGSDURGHJGSDURG";
        var key = TwoFishKeyGenerator.generateKey();
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.CFB, key);
        byte[] encrypted = cryptography.encrypt(data.getBytes(), initVector.getBytes());
        byte[] decrypted = cryptography.decrypt(encrypted, initVector.getBytes());
        assertEquals(data, new String(decrypted));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Hello world", "12345678901234567890", "some large text to test normalize and denormalize data"})
    void OFBTests(String data) throws InvalidKeyException, KeyLenException {
        String initVector = "HJGSDURGHJGSDURG";
        var key = TwoFishKeyGenerator.generateKey();
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.OFB, key);
        byte[] encripted = cryptography.encrypt(data.getBytes(), initVector.getBytes());
        byte[] decripted = cryptography.decrypt(encripted, initVector.getBytes());
        assertEquals(data, new String(decripted));
    }
}
