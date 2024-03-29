/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 28, 2024
 *
 * This class handles the encryption and decryption with different methods as necessary
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class Encryption {

    //data is the plaintext to be encrypted
    // privateKey is the key used for encrypting

    /**
     * encrypts a given set of data using a privateKey to seed the RSA encryption
     * @param data
     *      the data to be encrypted
     * @param privateKey
     *      the key to drive the encryption
     * @return
     *      the encrypted byte[]
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encryptWithRSA(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //justRSA?

        //ENCRYPT_MODE is a mode constant used to specify that the Cipher instance should be initialized for encryption operations.
        //the cipher will use the privateKey to perform encryption
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);

        // encrypts the data and returns the resulting ciphertext
        return cipher.doFinal(data);
    }

    /**
     * decrypts a given set of data using RSA decryption
     * @param data
     *      the data to be decrypted
     * @param publicKey
     *      the key used for decryption
     * @return
     *      the decrypted byte[]
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decryptWithRSA(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }


    /**
     * encrypts a given set of data using AES
     * @param data
     *      the data to be encrypted
     * @param secretKey
     *      the secret key needed for encryption
     * @param IV
     *      the initialization vector to start the cipher block chaining
     * @return
     *      the encrypted data[]
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] encryptWithAES(byte[] data, byte[] secretKey, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecretKeySpec keyspec = new SecretKeySpec(secretKey,"AES");
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, IV);

        return cipher.doFinal(data);
    }

    /**
     * decrypts a set of data using AES
     * @param data
     *      the data to be decrypted
     * @param secretKey
     *      the secret key used in the decryption
     * @param IV
     *      the initialization vector for the decryption
     * @return
     *      the decrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] decryptWithAES(byte[] data, byte[] secretKey, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecretKeySpec keyspec = new SecretKeySpec(secretKey,"AES");

        cipher.init(Cipher.DECRYPT_MODE, keyspec, IV);

        return cipher.doFinal(data);
    }
}
