/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 26, 2024
 *
 * This class handles the Diffie-Hellman functions--key generation
 */

import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {
    // This number is taken from RCF 3526, and the radix of 16 indicates that this is given in hex
    // https://www.ietf.org/rfc/rfc3526.txt
    public static final BigInteger N = new BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    //use the valueOf method as there is no implicit conversion from int to BigInteger
    public static final BigInteger g = BigInteger.valueOf(2); // Generator

    /**
     * Method that makes a random private key
     * @return
     *      a randomly generated number that is less than N
     */
    public static BigInteger generatePrivateKey(){
        // The secure random class is used to ensure that the generated private keys are secure,
        // unpredictable, and resistant to attacks.
        SecureRandom random = new SecureRandom();

        // Generate 2047-bit random number
        // 2047 is used here to ensure that we get a smaller number than the 2048-bit modulus used in N.
        // It needs to be smaller for the algorithm to work correctly
        return new BigInteger(2047, random);

    }

    /**
     * computes a public key when given a private key
     * @param myPrivateKey
     *      the private key for generation
     * @return
     *      the computed public key
     */
    public static BigInteger computePublicKey(BigInteger myPrivateKey){
        return g.modPow(myPrivateKey,N);// g^a mod N
    }


    /**
     * computes the shared secret, given two keys
     * @param myPrivateKey
     *      the private key for the caller
     * @param theirPublicKey
     *      the public key from the counterpart
     * @return
     *      the shared secret
     */
    public static BigInteger computeSharedSecret(BigInteger myPrivateKey, BigInteger theirPublicKey){
        // BigInteger sharedSecretA = B.modPow(a, N); // sharedSecretA = B^a mod N
        // BigInteger sharedSecretB = A.modPow(b, N); // sharedSecretB = A^b mod N
        return theirPublicKey.modPow(myPrivateKey, N);
    }

    /**
     * compares the shared secrets, used in debugging in BasicMain
     * @param sharedSecretA
     *      the sharedSecret for one user
     * @param sharedSecretB
     *      the shared secret for another user
     * @return
     */
    public static boolean compareSharedSecrets(BigInteger sharedSecretA, BigInteger sharedSecretB){
        return sharedSecretA.equals(sharedSecretB);
    }
}