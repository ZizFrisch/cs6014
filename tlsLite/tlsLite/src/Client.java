/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 28, 2024
 *
 * This class represents the client in the client/server relationship
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;


public class Client {
    private static PrivateKey clientRSAPriv;
    private static Certificate clientRSAPub;
    private static Certificate CAcertificate;
    private static ArrayList<byte[]> messageHistory;
    private static KeyGenerator clientKeys;

    /**
     * This is a helper method that initializes a bunch of initial parameters
     */
    private static void initializeParameters(){
        // client reads in the RSA key pairs: clientRSAPriv and clientRSAPub
        // client reads in the CA certificate
        // Diffie-Hellman parameters (g and N) are static members of that class and do not need to be initialized
        try {
            clientRSAPriv = Handshake.readPrivateKey("../clientPrivateKey.der");
            clientRSAPub = Handshake.readCertificate("../CASignedClientCertificate.pem");

            CAcertificate = Handshake.readCertificate("../CAcertificate.pem");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //create an array that will hold all sent/received messages
        messageHistory = new ArrayList<>();

        //create an instance of a KeyGenerator
        clientKeys = new KeyGenerator();
    }

    public static void main(String[] args) throws IOException {

        //  1. Initialization:
        initializeParameters();

        //set up server
        int server_port = 5678;
        Socket socket = new Socket("localhost", server_port);

        boolean handshakeCompleted = false;

        // Execute the Handshake
        try {
            System.out.println("Beginning Handshake");
            handshakeCompleted = Handshake.clientHandshake(socket, messageHistory, clientRSAPriv, clientRSAPub, CAcertificate, clientKeys);
        } catch (ClassNotFoundException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        if(handshakeCompleted){
            System.out.println("Handshake Completed Successfully");
        }

        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

        // receive messages from server
        try {
            byte[] helloMessageArray = Message.receiveMessage(objectInputStream, messageHistory);
            byte[] decryptedHelloMessage = Encryption.decryptWithAES(helloMessageArray, clientKeys.serverEncryptArray, clientKeys.serverIV);
            String hello =  new String(Message.checkMessage(clientKeys.serverMAC,decryptedHelloMessage, messageHistory), StandardCharsets.UTF_8);
            System.out.println("Message received: " + hello);

            byte[] TLSMessageArray = Message.receiveMessage(objectInputStream, messageHistory);
            byte[] decryptedTLSMessage = Encryption.decryptWithAES(TLSMessageArray, clientKeys.serverEncryptArray, clientKeys.serverIV);
            String TLSMessage =  new String(Message.checkMessage(clientKeys.serverMAC,decryptedTLSMessage, messageHistory), StandardCharsets.UTF_8);
            System.out.println("Message received: " + TLSMessage);

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

            if(hello.equals("Hello client!") && TLSMessage.equals("TLSlite is complete :)")){
                // send message to server if we got what we expected
                String congratsMessage = "Correct messages received--Congratulations Server!";
                byte[] message = congratsMessage.getBytes();
                System.out.println("Sending Response Message to Server: " + congratsMessage);

                Message.encryptAndSendMessage(message, clientKeys.clientMAC, clientKeys.clientEncryptArray, clientKeys.clientIV, objectOutputStream, messageHistory);
            }
            else{
                throw new RuntimeException("Did not receive the expected messages from the Server");
            }
        } catch (ClassNotFoundException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                 IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        socket.close();
        System.out.println("Client socket closed");
    }
}

