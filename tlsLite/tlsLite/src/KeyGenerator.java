/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 26, 2024
 *
 * This class handles the key generation of the session keys
 */


import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class KeyGenerator {
    public SecretKey serverEncrypt;
    public SecretKey clientEncrypt;
    public SecretKey serverMAC;
    public SecretKey clientMAC;
    public IvParameterSpec serverIV;
    public IvParameterSpec clientIV;

    //the same keys, but in byte array form... in case they are needed later (some were used in encryption)
    public byte[] serverEncryptArray;
    public byte[] clientEncryptArray;
    public byte[] serverMACArray;
    public byte[] clientMACArray;
    public byte[] serverIVArray;
    public byte[] clientIVArray;



    //    function hdkfExpand(input, tag): // tag is a string, but that's easily converted to byte[]
    //    okm = HMAC(key = input,  data = tag concatenated with a byte with value 1)
    //   return first 16 bytes of okm

    /**
     * Diffie-Hellman gives us a shared secret key, but it might be too small or be otherwise unsuitable to use as keys for AES or MACs.
     * We'll run it through a key derivation function (KDF) to turn it into a bunch of nice, random-looking keys. This function manages
     * the expansion of the keys.
     * @param input
     *      the array to be expanded
     * @param tag
     *      a tag so that the keys aren't confused
     * @return
     *      a new byte array that is the last 16 bytes of the generated array
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private byte[] hdkfExpand(byte[] input, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
        //concatenate the tag with a byte value: 1
        byte[] tagData = Arrays.copyOf(tag.getBytes(),tag.getBytes().length +1);
        tagData[tagData.length - 1] = 0x01;

        //compute HMAC with input as key and data as input
        //create a MAC instance
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(input, "HmacSHA256" );
        //initialize the MAC instance
        hmac.init(secret_key);

        byte[] okm = hmac.doFinal(tagData);

        //return the first 16 bytes of the output
        return Arrays.copyOf(okm, 16);
    }

    /**
     * The driver of the key chaining. The nonce is used to start the HMAC sequence
     * @param clientNonce
     *      the nonce used to start the driving
     * @param sharedSecret
     *      the shared DH secret
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void makeSecretKeys(BigInteger clientNonce, BigInteger sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] nonceArray = clientNonce.toByteArray();
        byte[] sharedSecretArray = sharedSecret.toByteArray();

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(nonceArray, "HmacSHA256"));
        byte[] prk = hmac.doFinal(sharedSecretArray);

        serverEncryptArray = hdkfExpand(prk, "server encrypt");
        serverEncrypt = new SecretKeySpec(serverEncryptArray, "AES/CBC/PKCS5Padding" );

        clientEncryptArray = hdkfExpand(serverEncryptArray, "client encrypt");
        clientEncrypt = new SecretKeySpec(clientEncryptArray, "AES/CBC/PKCS5Padding" );

        serverMACArray = hdkfExpand(clientEncryptArray, "server MAC");
        serverMAC = new SecretKeySpec(serverMACArray, "HmacSHA256" );

        clientMACArray = hdkfExpand(serverMACArray, "client MAC");
        clientMAC = new SecretKeySpec(clientMACArray, "HmacSHA256" );

        serverIVArray = hdkfExpand(clientMACArray, "server IV");
        serverIV = new IvParameterSpec(serverIVArray);

        clientIVArray = hdkfExpand(serverIVArray, "clientIV");
        clientIV = new IvParameterSpec(clientIVArray);

        //    prk = HMAC(key = clientNonce, data = sharedSecretFromDiffieHellman)
        //    serverEncrypt = hkdfExpand(prk, "server encrypt")
        //    clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt")
        //    serverMAC = hkdfExpand(clientEncrypt, "server MAC")
        //    clientMAC = hkdfExpand(serverMAC, "client MAC")
        //    serverIV = hkdfExpand(clientMAC, "server IV")
        //    clientIV = hkdfExpand(serverIV, "client IV")
    }

    /**
     * compares the secret keys from two different instances of the keyGenerator class. Used in testing/debugging in BasicMain
     * @param client
     *      -- one keyGenerator
     * @param server
     *      -- another keyGenerator
     * @return
     *      -- true if all secret keys are the same
     */
    public static boolean compareSecretKeys(KeyGenerator client, KeyGenerator server){
        boolean result = true;
        if(!client.serverEncrypt.equals(server.serverEncrypt)){
            System.out.println("serverEncrypt not equal");
            result = false;
        }
        if(!client.clientEncrypt.equals(server.clientEncrypt)){
            System.out.println("clientEncrypt not equal");
            result = false;
        }
        if(!client.serverMAC.equals(server.serverMAC)){
            System.out.println("serverMAC not equal");
            result = false;
        }
        if(!client.clientMAC.equals(server.clientMAC)){
            System.out.println("clientMAC not equal");
            result = false;
        }
        if(!Arrays.equals(client.serverIV.getIV(), server.serverIV.getIV())){
            System.out.println("serverIV not equal");
            System.out.println("client serverIV: " + Arrays.toString(client.serverIV.getIV()));
            System.out.println("server serverIV: " + Arrays.toString(server.serverIV.getIV()));
            result = false;
        }
        if(!Arrays.equals(client.clientIV.getIV(), server.clientIV.getIV())){
            System.out.println("clientIV not equal");
            System.out.println("client clientIV: " + Arrays.toString(client.clientIV.getIV()));
            System.out.println("server clientIV: " + Arrays.toString(server.clientIV.getIV()));
            result = false;
        }

        if(!Arrays.equals(client.serverEncryptArray, server.serverEncryptArray)){
            System.out.println("serverEncrypt not equal");
            result = false;
        }
        if(!Arrays.equals(client.clientEncryptArray, server.clientEncryptArray)){
            System.out.println("clientEncrypt not equal");
            result = false;
        }
        if(!Arrays.equals(client.serverMACArray, server.serverMACArray)){
            System.out.println("serverMAC not equal");
            result = false;
        }
        if(!Arrays.equals(client.clientMACArray, server.clientMACArray)){
            System.out.println("clientMAC not equal");
            result = false;
        }
        if(!Arrays.equals(client.serverIVArray, server.serverIVArray)){
            System.out.println("serverIV not equal");
            System.out.println("client serverIV: " + Arrays.toString(client.serverIV.getIV()));
            System.out.println("server serverIV: " + Arrays.toString(server.serverIV.getIV()));
            result = false;
        }
        if(!Arrays.equals(client.clientIVArray, server.clientIVArray)){
            System.out.println("clientIV not equal");
            System.out.println("client clientIV: " + Arrays.toString(client.clientIV.getIV()));
            System.out.println("server clientIV: " + Arrays.toString(server.clientIV.getIV()));
            result = false;
        }
        return result;
    }
}
