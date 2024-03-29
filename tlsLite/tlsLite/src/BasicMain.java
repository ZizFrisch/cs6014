/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 26, 2024
 *
 * This Main was essentially the practice run of TLS before the networking was implemented.
 * The basic concepts were built and debugged before implementing sockets and streams.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public class BasicMain {
    public static void main(String[] args) throws CertificateEncodingException {
        //  1. Initialization:
        //  Both server and client have RSA key pairs (serverRSAPriv, serverRSAPub,
        //  clientRSAPriv, clientRSAPub) and Diffie-Hellman parameters (g and N) agreed upon.
        // the agreed upon Diffie-Hellman parameters are static members of that class

        //also initialize object Arrays for the client and server to track what they've received.

        ArrayList<byte[]> allServerMessages = new ArrayList<>();
        ArrayList<byte[]> allClientMessages = new ArrayList<>();

//        ArrayList<byte[]> serverReceived = new ArrayList<>();
//        ArrayList<byte[]> clientSent = new ArrayList<>();
//        ArrayList<Object> clientReceived = new ArrayList<>();

        PrivateKey serverRSAPriv;
        Certificate serverRSAPub;
        PrivateKey clientRSAPriv;
        Certificate clientRSAPub;
        PrivateKey CAPrivateKey;
        Certificate CAcertificate;

        try {
            serverRSAPriv = Handshake.readPrivateKey("../serverPrivateKey.der");
            serverRSAPub = Handshake.readCertificate("../CASignedServerCertificate.pem");

            clientRSAPriv = Handshake.readPrivateKey("../clientPrivateKey.der");
            clientRSAPub = Handshake.readCertificate("../CASignedClientCertificate.pem");

            CAcertificate = Handshake.readCertificate("../CAcertificate.pem");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }


        // 2. Diffie-Hellman Key Exchange:
        // Server and client each generate random secret keys (serverDHPriv, clientDHPriv) for Diffie-Hellman.
        // They derive public keys: serverDHPub = g^serverDHPriv mod N and clientDHPub = g^clientDHPriv mod N.

        // Step a: Generate private key for both parties
        BigInteger clientDHprivateKey = DiffieHellman.generatePrivateKey(); //client private key
        BigInteger serverDHPrivateKey = DiffieHellman.generatePrivateKey(); //server private key

        // Step b: Compute public key for both parties
        BigInteger clientDHPublicKey = DiffieHellman.computePublicKey(clientDHprivateKey);
        BigInteger serverDHPublicKey = DiffieHellman.computePublicKey(serverDHPrivateKey);


        // 3. Client Initialization:
        // Client generates a random nonce (clientNonce) using a secure random generator.
        BigInteger nonce = Handshake.generateNonce();

        // 4. Handshake
        //client sends Nonce
        allClientMessages.add(nonce.toByteArray());
        //server receives
        allServerMessages.add(nonce.toByteArray());

//        clientSent.add(nonce.toByteArray());
//        serverReceived.add(nonce.toByteArray());


        // serverRSAPriv (in the server private-key file),
        // serverRSAPub (in the server certificate file),
        // clientRSAPriv (in the client private-key file),
        // and clientRSAPub (in the client certificate file).

        //server responds:
        // Server sends its certificate (serverRSAPub), serverDHPub,
        // and a signed Diffie-Hellman public key encrypted with its private key -- the encryption is the signature?
        // (Enc(serverRSAPriv, serverDHPub)).
        byte[] encServerDHPub;
        try {
            encServerDHPub = Encryption.encryptWithRSA(serverDHPublicKey.toByteArray(), serverRSAPriv);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //server sends
        allServerMessages.add(serverRSAPub.getEncoded());
        allServerMessages.add(serverDHPublicKey.toByteArray());
        allServerMessages.add(encServerDHPub);
        //client receives the same
        allClientMessages.add(serverRSAPub.getEncoded());
        allClientMessages.add(serverDHPublicKey.toByteArray());
        allClientMessages.add(encServerDHPub);


        //client responds:
        // Client sends its certificate (clientRSAPub), its Diffie-Hellman public key (clientDHPub),
        // and a signed Diffie-Hellman public key encrypted with its private key
        // (Enc(clientRSAPriv, clientDHPub)).
        byte[] encClientDHPub;
        try{
            encClientDHPub = Encryption.encryptWithRSA(clientDHPublicKey.toByteArray(), clientRSAPriv);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        //client sends
        allClientMessages.add(clientRSAPub.getEncoded());
        allClientMessages.add(clientDHPublicKey.toByteArray());
        allClientMessages.add(encClientDHPub);
        //server receives
        allServerMessages.add(clientRSAPub.getEncoded());
        allServerMessages.add(clientDHPublicKey.toByteArray());
        allServerMessages.add(encClientDHPub);

        // 5. Certificate Validation
        // Both client and server verify the received certificates against the CA's certificates they both know.

        try{
            //SERVER VALIDATES CLIENT
            //received clientRSAPub, clientDHPub, and encClientDHPub
            // use the authority's public key as the argument for the verify method
            clientRSAPub.verify(CAcertificate.getPublicKey());
            //decrypt and make sure they match
            byte[] decClientDHPub = Encryption.decryptWithRSA(encClientDHPub,clientRSAPub.getPublicKey());
            if(!Arrays.equals(decClientDHPub, clientDHPublicKey.toByteArray())){
                System.out.println("DHkeys decrypted incorrectly");
                throw new RuntimeException();
            }

            //CLIENT VALIDATES SERVER
            // received (serverRSAPub), serverDHPub, and encServerDHPub
            // client verifies the key against the one expected from the server
            serverRSAPub.verify(CAcertificate.getPublicKey());
            //decrypt and make sure they match
            byte[] decServerDHPub = Encryption.decryptWithRSA(encServerDHPub, serverRSAPub.getPublicKey());
            if(!Arrays.equals(decServerDHPub, serverDHPublicKey.toByteArray())){
                System.out.println("DHkeys decrypted incorrectly");
                throw new RuntimeException();
            }
        } catch (InvalidKeyException e) {
            System.out.println("Key was not signed");
            // certificate was not signed with given public key
            return;
        } catch (NoSuchAlgorithmException |
                 NoSuchProviderException |
                 SignatureException |
                 CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            //something went wrong in decryption
            throw new RuntimeException(e);
        }


        // 6. Compute Shared Secret
        // Both parties compute the shared Diffie-Hellman secret using the received public keys and their own private keys.
        BigInteger clientDHSharedSecret = DiffieHellman.computeSharedSecret(clientDHprivateKey,serverDHPublicKey);
        BigInteger serverDHSharedSecret = DiffieHellman.computeSharedSecret(serverDHPrivateKey,clientDHPublicKey);

        //compare shared secret keys for accuracy
        assert(DiffieHellman.compareSharedSecrets(clientDHSharedSecret,serverDHSharedSecret));
        if(!DiffieHellman.compareSharedSecrets(clientDHSharedSecret,serverDHSharedSecret)){
            System.out.println("Shared secrets are not equal");
        }

        // 7. Key Derivation
        // Using the shared secret as the master key, both parties derive session keys
        // (encryption keys, MAC keys, and IVs) using a Key Derivation Function (KDF) like HKDF.
        KeyGenerator clientGenerator = new KeyGenerator();
        KeyGenerator serverGenerator = new KeyGenerator();

        try{
            clientGenerator.makeSecretKeys(nonce,clientDHSharedSecret);
            serverGenerator.makeSecretKeys(nonce,serverDHSharedSecret);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        boolean passed = KeyGenerator.compareSecretKeys(clientGenerator, serverGenerator);
        if(!passed){
            throw new RuntimeException("Secret Keys are not all equal");
        }


        // 8. Finish Handshake:
        // Server sends HMAC:
        // Server sends HMAC of all handshake messages (including its own) using its MAC key.

        //concat all messages sent/received by server til now
        byte[] serverConcatenated = Message.concatenate(allServerMessages);
        //make a hash of all the server messages
        byte[] serverHMAC = Message.getHMACHash(serverGenerator.serverMAC,serverConcatenated);
        //concat the messages with the hash
        byte[] serverHistoryHash = Message.concatenate(serverConcatenated,serverHMAC);
        //encrypt the messages with the server key
        byte[] encServerHistoryHash;
        try{
            encServerHistoryHash = Encryption.encryptWithAES(serverHistoryHash, serverGenerator.serverEncryptArray, serverGenerator.serverIV);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //server sends the encoded hash, client receives the hash
        allServerMessages.add(encServerHistoryHash);
        allClientMessages.add(encServerHistoryHash);

        // Client sends HMAC:
        // client checks that what they received equals what they sent
        // decrypt first(?)
        byte[] clientLastMessage = allClientMessages.getLast();
        byte[] decryptedHashFromServer;
        try{
            decryptedHashFromServer = Encryption.decryptWithAES(clientLastMessage,clientGenerator.serverEncryptArray, clientGenerator.serverIV);
        } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException |
                 IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        //hashlength is 32, so remove that
        byte[] isolatedMessage = Arrays.copyOf(decryptedHashFromServer, decryptedHashFromServer.length-32);
        byte[] receivedHash = new byte[32];
        //isolate the hash
        System.arraycopy(decryptedHashFromServer, decryptedHashFromServer.length-32, receivedHash, 0, 32);
        //client needs to calculate the hash they would have received
        //checks that the message I received is correct per before the encryption/decryption
        if(!Arrays.equals(isolatedMessage, serverConcatenated)){
            System.out.println("isolated message:   " + Arrays.toString(isolatedMessage));
            System.out.println("serverConcatenated: " + Arrays.toString(serverConcatenated));
            System.out.println("messages not the same");
        }
        //client calculates the hash of what they've received so far
        allClientMessages.removeLast();
        byte[] expectedMessages = Message.concatenate(allClientMessages);
        allClientMessages.add(clientLastMessage);
        byte[] expectedHash = Message.getHMACHash(clientGenerator.serverMAC, expectedMessages);
        if(!Arrays.equals(expectedHash, receivedHash)){
            System.out.println("expected hash: " + Arrays.toString(expectedHash));
            System.out.println("received hash: " + Arrays.toString(receivedHash));
            throw new RuntimeException("Hashes are not equal on client end");
        }
        if(!Arrays.equals(expectedMessages, isolatedMessage)){
            throw new RuntimeException("Messages do not match in client");
        }

        // Client sends HMAC of all handshake messages (including server's HMAC) using its MAC key.



        // 9. Authentication Complete:
        // At this point, both client and server have authenticated each other and derived session keys for secure communication.



        // 10. send messages
//        After the handshake, each message will use a format similar to the TLS record format,
//        but we'll let Java take care of the specifics by making use of the ObjectOutputStream and ObjectInputStream classes.
//
//        To send a message:
//
//        Compute the HMAC of the message using the appropriate MAC key
//        Use the cipher object to encrypt the message data concatenated with the MAC
//        Send/receive the resulting byte array using the ObjectOutputStream/ObjectIntputStream classes (it will include the array size, etc automatically). You'll want to use the readObject/writeObject methods.
//        For encryption, we'll use AES 128 in CBC mode. For MAC, we'll use HMAC using SHA-256 as our hash function.

        System.out.println("Reached the end with no crashes :)");
    }
}

