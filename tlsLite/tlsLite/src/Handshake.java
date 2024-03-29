/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 26, 2024
 *
 * This class handles the functionality of the handshake. The two main methods (clientHandshake and serverHandshake) are quite hefty.
 * future improvements on this code will include further factorization of these methods to improve readability
 */

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

public class Handshake {

    /**
     * generates the client nonce, which is a random 32 bit BigInteger
     * @return
     *      the nonce
     */
    public static BigInteger generateNonce(){
        SecureRandom random = new SecureRandom();
        return new BigInteger(32,random);
    }

    /**
     * reads a Private Key from a file
     * @param filePath
     *      the path where the file is found
     * @return
     *      the private key that was read in
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey readPrivateKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //read the key file
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));

        // Create a PKCS8EncodedKeySpec with the key bytes
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Get a keyfactor for RSA--what algorithm are we using?
        KeyFactory factory = KeyFactory.getInstance("RSA");

        //Generate the PrivateKey object from the key specification
        return factory.generatePrivate(keySpec);
    }


    /**
     * reads a certificate from a file
     * @param filePath
     *      the path where the file can be found
     * @return
     *      the created certificate from the file
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws CertificateException
     */
    public static Certificate readCertificate(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        InputStream certificateInputStream = new FileInputStream(filePath);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        certificateInputStream.close();

        return certificate;
    }


    @SuppressWarnings("unchecked") // Suppress unchecked cast warning
/**
 * helper method to read an object type. I haven't been able to get this to work successfully, but may refactor later to include this to clean up my code more
 */
    public static <T> T readObjectWithType(ObjectInputStream objectInputStream, Class<T> expectedType) throws IOException, ClassNotFoundException {
        // Read the object from the input stream
        Object obj = objectInputStream.readObject();

        // Check if the object is an instance of the expected type
        if (expectedType.isInstance(obj)) {
            // Cast the object to the expected type
            return (T) obj;
        } else {
            // Throw an exception if the received object is not of the expected type
            throw new RuntimeException("Received object is not of the expected type: " + expectedType.getName());
        }
    }


    /**
     * this encompasses one entire "step" of the handshake. The step where the certificate, DHpublic key, and encrypted DHpublic key are sent
     * Note: I don't love this method and would prefer that it was broken up in a different way. But here we are. My main gripe with it is that
     * the matching "receive" method wasn't working and gave me null pointer exceptions. I hope to improve future versions of this code to include the
     * "receive" method, or refactor it in a different way.
     * @param DHPublicKey
     *      the DH key to be sent
     * @param RSAPrivateKey
     *      the key used to encrypt the DH public key
     * @param RSAPublicKey
     *      the certificate to be sent
     * @param objectOutputStream
     *      the stream that will be written to
     * @param messageHistory
     *      the message history of the caller
     * @throws IOException
     * @throws CertificateEncodingException
     */
    private static void sendCertificatesandDiffieHellman(BigInteger DHPublicKey, PrivateKey RSAPrivateKey, Certificate RSAPublicKey, ObjectOutputStream objectOutputStream, ArrayList<byte[]> messageHistory ) throws IOException, CertificateEncodingException {
        // Caller sends its certificate (serverRSAPub), serverDHPub,
        // and a signed Diffie-Hellman public key encrypted with its private key -- the encryption is the signature?
        // (Enc(serverRSAPriv, serverDHPub)).
        byte[] encServerDHPub;
        try {
            encServerDHPub = Encryption.encryptWithRSA(DHPublicKey.toByteArray(), RSAPrivateKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //send messages and add them to history
        objectOutputStream.writeObject(RSAPublicKey);
        messageHistory.add(RSAPublicKey.getEncoded());

        objectOutputStream.writeObject(DHPublicKey);
        messageHistory.add(DHPublicKey.toByteArray());

        objectOutputStream.writeObject(encServerDHPub);
        messageHistory.add(encServerDHPub);
    }

//    private static void receiveCertificatesandDiffieHellman(Certificate RSAPublicKey, BigInteger DHPublicKey, byte[] encDHPub, ObjectInputStream objectInputStream, ArrayList<byte[]> messageHistory) throws IOException, ClassNotFoundException, CertificateEncodingException {
//        Object obj;
//        obj = objectInputStream.readObject();
//        // Check if the object is an instance of Certificate
//        if (obj instanceof Certificate) {
//            // Cast the object to BigInteger
//            RSAPublicKey = (Certificate) obj;
//            // Now you can use the BigInteger as needed
//            System.out.println("Read Certificate: serverRSAPub");
//        } else {
//            // Handle the case where the received object is not a BigInteger
//            throw new RuntimeException("Received RSAPublicKey is not a Certificate");
//        }
//        //add it to all messages
//        messageHistory.add(RSAPublicKey.getEncoded());
//
//        obj = objectInputStream.readObject();
//        // Check if the object is an instance of BigInteger
//        if (obj instanceof BigInteger) {
//            // Cast the object to BigInteger
//            DHPublicKey = (BigInteger) obj;
//            // Now you can use the BigInteger as needed
//            System.out.println("Read BigInteger: " + DHPublicKey);
//        } else {
//            // Handle the case where the received object is not a BigInteger
//            throw new RuntimeException("Received nonce is not a BigInteger");
//        }
//        //add it to all messages
//        messageHistory.add(DHPublicKey.toByteArray());
//
//        obj = objectInputStream.readObject();
//        if (obj instanceof byte[]) {
//            // Cast the object to BigInteger
//            encDHPub = (byte[]) obj;
//            // Now you can use the BigInteger as needed
//            System.out.println("Read byte[]: " + encDHPub);
//        } else {
//            // Handle the case where the received object is not a BigInteger
//            throw new RuntimeException("Received encServerDHPub is not a byteArray");
//        }
//        messageHistory.add(encDHPub);
//    }

    /**
     * The Driver Method for the client handshake. This is quite a hefty function and should really be factored out more.
     * @param socket
     *      -- the socket that belongs to the client for input/output
     * @param messageHistory
     *      -- an arraylist of byte[] that tracks all messages sent/received through the network by the client
     * @param clientRSAPriv
     *      -- the client's private RSA key that was read in from a .der file
     * @param clientRSAPub
     *      -- the client's certificate that was read in from a .pem file
     * @param CAcertificate
     *      -- the certificate authority certificate ("keycorp") that was read in from a file
     * @param sessionKeys
     *      -- the session keys that belong to the client
     * @return
     *      -- returns true if the handshake was completed successfully
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws CertificateEncodingException
     */
    public static boolean clientHandshake(Socket socket, ArrayList<byte[]> messageHistory, PrivateKey clientRSAPriv, Certificate clientRSAPub, Certificate CAcertificate, KeyGenerator sessionKeys) throws IOException, ClassNotFoundException, CertificateEncodingException {
        // 2. Diffie-Hellman Key Exchange:
        // Step a: Generate a random private key
        BigInteger clientDHPrivateKey = DiffieHellman.generatePrivateKey(); //client private key
        // Step b: Derive public key clientDHPub = g^clientDHPriv mod N.
        BigInteger clientDHPublicKey = DiffieHellman.computePublicKey(clientDHPrivateKey);

        // 3. Client Initialization:
        // Client generates a random nonce (clientNonce) using a secure random generator.
        BigInteger nonce = Handshake.generateNonce();

        //wrap the output stream to become an ObjectOutputStream:
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

        //----------------------BEGIN THE HANDSHAKE------------------//
        // 4. Handshake
        //client sends Nonce
        objectOutputStream.writeObject(nonce);
        messageHistory.add(nonce.toByteArray());

        //server responds:
        // Server sends its certificate (serverRSAPub), serverDHPub,
        // and a signed Diffie-Hellman public key encrypted with its private key -- this encryption is considered a signature
        // (Enc(serverRSAPriv, serverDHPub)).
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
        Certificate serverRSAPub;
        BigInteger serverDHPublicKey;
        byte[] encServerDHPub;
//        receiveCertificatesandDiffieHellman( serverRSAPub, serverDHPub, encServerDHPub,  objectInputStream,  messageHistory);

        Object obj;
        obj = objectInputStream.readObject();
        // Check if the object is an instance of Certificate
        if (obj instanceof Certificate) {
            // Cast the object to Certificate
            serverRSAPub = (Certificate) obj;
            //System.out.println("Read Certificate: serverRSAPub");
        } else {
            // Handle the case where the received object is not a Certificate
            throw new RuntimeException("Received server RSAPub is not a Certificate");
        }
        //add it to all messages
        messageHistory.add(serverRSAPub.getEncoded());

        obj = objectInputStream.readObject();
        // Check if the object is an instance of BigInteger
        if (obj instanceof BigInteger) {
            // Cast the object to BigInteger
            serverDHPublicKey = (BigInteger) obj;
            //System.out.println("Read BigInteger: " + serverDHPublicKey);
        } else {
            // Handle the case where the received object is not a BigInteger
            throw new RuntimeException("Received serverDHPublicKey is not a BigInteger");
        }
        //add it to all messages
        messageHistory.add(serverDHPublicKey.toByteArray());

        obj = objectInputStream.readObject();
        if (obj instanceof byte[]) {
            // Cast the object to byte[]
            encServerDHPub = (byte[]) obj;
            //System.out.println("Read byte[]: " + encServerDHPub);
        } else {
            // Handle the case where the received object is not a byte[]
            throw new RuntimeException("Received encServerDHPub is not a byteArray");
        }
        messageHistory.add(encServerDHPub);


        //client responds:
        // Client sends its certificate (clientRSAPub), its Diffie-Hellman public key (clientDHPub),
        // and a signed Diffie-Hellman public key encrypted with its private key
        // (Enc(clientRSAPriv, clientDHPub)).
        sendCertificatesandDiffieHellman( clientDHPublicKey,  clientRSAPriv, clientRSAPub, objectOutputStream,  messageHistory );

        // 5. Certificate Validation
        // Both client and server verify the received certificates against the CA's certificates they both know.
        try{
            //CLIENT VALIDATES SERVER
            // received (serverRSAPub), serverDHPub, and encServerDHPub
            // client verifies the key against the one expected from the server
            serverRSAPub.verify(CAcertificate.getPublicKey());
            //decrypt the DH key and make sure it matches the expected one
            byte[] decServerDHPub = Encryption.decryptWithRSA(encServerDHPub, serverRSAPub.getPublicKey());
            if(!Arrays.equals(decServerDHPub, serverDHPublicKey.toByteArray())){
                throw new RuntimeException("DH keys decrypted incorrectly");
            }
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key was not signed");
            // certificate was not signed with given public key
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
        BigInteger clientDHSharedSecret = DiffieHellman.computeSharedSecret(clientDHPrivateKey,serverDHPublicKey);


        // 7. Key Derivation
        // Using the shared secret as the master key, both parties derive session keys
        // (encryption keys, MAC keys, and IVs) using a Key Derivation Function (KDF) like HKDF.
        try{
            sessionKeys.makeSecretKeys(nonce,clientDHSharedSecret);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        // 8. Finish Handshake -- History Hash
        // Receive Server History Hash
        byte[] serverHistoryHash;
        obj = objectInputStream.readObject();
        if (obj instanceof byte[]) {
            // Cast the object to byte[]
            serverHistoryHash = (byte[]) obj;
            //System.out.println("Read Server History Hash: ");
        } else {
            // Handle the case where the received object is not a byte[]
            throw new RuntimeException("Received encServerDHPub is not a byte[]");
        }
        messageHistory.add(serverHistoryHash);

        //decrypt the hash
        byte[] decryptedHashFromServer;
        try{
            decryptedHashFromServer = Encryption.decryptWithAES(serverHistoryHash,sessionKeys.serverEncryptArray, sessionKeys.serverIV);
        } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException |
                 IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        //compares the hash to ensure that we received what we thought we would
        Message.checkMessage(sessionKeys.serverMAC,decryptedHashFromServer, messageHistory);

        // Client sends HMAC of all handshake messages (including server's HMAC) using its MAC key.
        byte[] clientConcatenated = Message.concatenate(messageHistory);
        Message.encryptAndSendMessage(clientConcatenated, sessionKeys.clientMAC, sessionKeys.clientEncryptArray, sessionKeys.clientIV,  objectOutputStream, messageHistory);

        //if we got here without throwing any exceptions then the Handshake was successful :)
        return true;
    }


    /**
     *  The Driver Method for the server handshake. This is quite a hefty function and should really be factored out more.
     * @param socket
     *      -- the socket that belongs to the server for input/output
     * @param messageHistory
     *      -- an arraylist of byte[] that tracks all messages sent/received through the network by the server
     * @param serverRSAPriv
     *      -- the server's private RSA key that was read in from a .der file
     * @param serverRSAPub
     *      -- the server's certificate that was read in from a .pem file
     * @param CAcertificate
     *      -- the certificate authority certificate ("keycorp") that was read in from a file
     * @param sessionKeys
     *      -- the session keys that belong to the server
     * @return
     *       -- returns true if the handshake was completed successfully
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws CertificateEncodingException
     */
    public static boolean serverHandshake(Socket socket, ArrayList<byte[]> messageHistory, PrivateKey serverRSAPriv, Certificate serverRSAPub, Certificate CAcertificate, KeyGenerator sessionKeys) throws IOException, ClassNotFoundException, CertificateEncodingException {
        // 2. Diffie-Hellman Key Exchange:
        // Step a: Generate a Diffie-Hellman private key for server
        BigInteger serverDHPrivateKey = DiffieHellman.generatePrivateKey(); //server private key

        // Step b: Derive public key for server: serverDHPub = g^serverDHPriv mod N
        BigInteger serverDHPublicKey = DiffieHellman.computePublicKey(serverDHPrivateKey);

        //get Object streams from socket
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

        //-------------------BEGIN HANDSHAKE------------------//
        //receive nonce from client
        Object obj = objectInputStream.readObject();
        BigInteger nonce;
        // Check if the object is an instance of BigInteger
        if (obj instanceof BigInteger) {
            // Cast the object to BigInteger
            nonce = (BigInteger) obj;
            //System.out.println("Read BigInteger: " + nonce);
        } else {
            // Handle the case where the received object is not a BigInteger
            throw new RuntimeException("Received nonce is not a BigInteger");
        }
        //add it to all messages
        messageHistory.add(nonce.toByteArray());

        // Note: this was an attempt to call my generic type function, but alas... it was unsuccessful.
        // Hopefully I will get it working in the future
//        try {
//            nonce = readObjectWithType(objectInputStream, BigInteger.class);
//            System.out.println("Read BigInteger: " + nonce);
//
//        } catch (IOException | ClassNotFoundException e) {
//            e.printStackTrace();
//            throw new RuntimeException("Reading Nonce Failed");
//        }

        //server responds:
        // Server sends its certificate (serverRSAPub), serverDHPub,
        // and a signed Diffie-Hellman public key encrypted with its private key -- the encryption is the signature?
        // (Enc(serverRSAPriv, serverDHPub)).
        sendCertificatesandDiffieHellman( serverDHPublicKey,  serverRSAPriv, serverRSAPub, objectOutputStream,  messageHistory );

        //client responds:
        // Client sends its certificate (clientRSAPub), its Diffie-Hellman public key (clientDHPub),
        // and a signed Diffie-Hellman public key encrypted with its private key
        // (Enc(clientRSAPriv, clientDHPub)).
        Certificate clientRSAPub;
        BigInteger clientDHPublicKey;
        byte[] encClientDHPub;
        //receiveCertificatesandDiffieHellman( clientRSAPub, clientDHPublicKey, encClientDHPub,  objectInputStream,  messageHistory);

        obj = objectInputStream.readObject();
        // Check if the object is an instance of Certificate
        if (obj instanceof Certificate) {
            // Cast the object to Certificate
            clientRSAPub = (Certificate) obj;
            //System.out.println("Read Certificate: serverRSAPub");
        } else {
            // Handle the case where the received object is not a Certificate
            throw new RuntimeException("Received RSAPublicKey is not a Certificate");
        }
        //add it to all messages
        messageHistory.add(clientRSAPub.getEncoded());

        obj = objectInputStream.readObject();
        // Check if the object is an instance of BigInteger
        if (obj instanceof BigInteger) {
            // Cast the object to BigInteger
            clientDHPublicKey = (BigInteger) obj;
            //System.out.println("Read BigInteger: " + clientDHPublicKey);
        } else {
            // Handle the case where the received object is not a BigInteger
            throw new RuntimeException("Received clientPublicKey is not a BigInteger");
        }
        //add it to all messages
        messageHistory.add(clientDHPublicKey.toByteArray());

        obj = objectInputStream.readObject();
        if (obj instanceof byte[]) {
            // Cast the object to byte[]
            encClientDHPub = (byte[]) obj;
            //System.out.println("Read byte[]: " + encClientDHPub);
        } else {
            // Handle the case where the received object is not a byte[]
            throw new RuntimeException("Received encServerDHPub is not a byte[]");
        }
        messageHistory.add(encClientDHPub);


        // 5. Certificate Validation
        // Both client and server verify the received certificates against the CA's certificates they both know.
        try{
            //SERVER VALIDATES CLIENT
            //received clientRSAPub, clientDHPub, and encClientDHPub
            // use the authority's public key as the argument for the verify method
            clientRSAPub.verify(CAcertificate.getPublicKey());
            //decrypt the DH public key and make sure it matches the expected
            byte[] decClientDHPub = Encryption.decryptWithRSA(encClientDHPub,clientRSAPub.getPublicKey());
            if(!Arrays.equals(decClientDHPub, clientDHPublicKey.toByteArray())){
                throw new RuntimeException("DHkeys decrypted incorrectly");
            }
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key was not signed");
            // certificate was not signed with given public key
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
        BigInteger serverDHSharedSecret = DiffieHellman.computeSharedSecret(serverDHPrivateKey,clientDHPublicKey);

        // 7. Key Derivation
        // Using the shared secret as the master key, both parties derive session keys
        // (encryption keys, MAC keys, and IVs) using a Key Derivation Function (KDF) like HKDF.
        try{
            sessionKeys.makeSecretKeys(nonce,serverDHSharedSecret);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        // 8. Finish Handshake -- HistoryHash
        // Server sends HMAC:
        // Server sends HMAC of all handshake messages (including its own) using its MAC key.

        //concat all messages sent/received by server til now
        byte[] serverConcatenated = Message.concatenate(messageHistory);
        //encrypt and send the full history.
        Message.encryptAndSendMessage(serverConcatenated, sessionKeys.serverMAC, sessionKeys.serverEncryptArray, sessionKeys.serverIV,  objectOutputStream, messageHistory);

        // receive the Client's HMAC of all handshake messages (including server's HMAC) using its MAC key.
        byte[] clientHistoryHash = Message.receiveMessage(objectInputStream, messageHistory);

        //decrypt the message
        byte[] decryptedHashFromClient;
        try{
            decryptedHashFromClient = Encryption.decryptWithAES(clientHistoryHash, sessionKeys.clientEncryptArray, sessionKeys.clientIV);
        } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException |
                 IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        //verify the message
        Message.checkMessage(sessionKeys.clientMAC,decryptedHashFromClient, messageHistory);

        //if we got to this point, then the handshake was successful and we can return true!
        return true;
    }

}
