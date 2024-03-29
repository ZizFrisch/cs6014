/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 28, 2024
 *
 * This class represents the server in the client/server relationship
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public class Server {

    private static PrivateKey serverRSAPriv;
    private static Certificate serverRSAPub;
    private static Certificate CAcertificate;
    private static ArrayList<byte[]> messageHistory;
    private static KeyGenerator serverKeys;

    /**
     * A helper method to initialize a bunch of parameters
     */
    private static void initializeParameters(){
        // server reads in the RSA key pairs: serverRSAPriv and serverRSAPub
        // server reads in the CA certificate
        // Diffie-Hellman parameters (g and N) are static members of that class and do not need to be initialized
        try {
            serverRSAPriv = Handshake.readPrivateKey("../serverPrivateKey.der");
            serverRSAPub = Handshake.readCertificate("../CASignedServerCertificate.pem");

            CAcertificate = Handshake.readCertificate("../CAcertificate.pem");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //create an array that will hold all sent/received messages
         messageHistory = new ArrayList<>();

        //create an instance of a keyGenerator
        serverKeys = new KeyGenerator();
    }


    public static void main(String[] args) throws IOException{
        int server_port = 5678;

        //  1. Initialization:
        initializeParameters();

        // set up Server
        ServerSocket listener = new ServerSocket(server_port);
        System.out.println("Listening at " + server_port);
        Socket socket = listener.accept();

        boolean handshakeCompleted = false;

        // Execute the handshake
        try {
            System.out.println("Beginning Handshake");
             handshakeCompleted = Handshake.serverHandshake(socket,  messageHistory, serverRSAPriv, serverRSAPub, CAcertificate, serverKeys);
        } catch (ClassNotFoundException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        if(handshakeCompleted){
            System.out.println("Handshake Successfully Completed");
        }

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

        // send two messages to client
        String Hello = "Hello client!";
        System.out.println("Sending message: " + Hello);
        byte[] message = Hello.getBytes();
        Message.encryptAndSendMessage(message, serverKeys.serverMAC, serverKeys.serverEncryptArray, serverKeys.serverIV, objectOutputStream, messageHistory);

        String TLS = "TLSlite is complete :)";
        System.out.println("Sending message: " + TLS);
        message = TLS.getBytes();
        Message.encryptAndSendMessage(message, serverKeys.serverMAC, serverKeys.serverEncryptArray, serverKeys.serverIV, objectOutputStream, messageHistory);

        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
        try {
            // receive message from client
            byte[] ConfirmationMsgArray = Message.receiveMessage(objectInputStream, messageHistory);
            byte[] decConfMsg = Encryption.decryptWithAES(ConfirmationMsgArray, serverKeys.clientEncryptArray, serverKeys.clientIV);
            String ConfMsg =  new String(Message.checkMessage(serverKeys.clientMAC,decConfMsg, messageHistory), StandardCharsets.UTF_8);
            System.out.println("Message received: " + ConfMsg);

            // if we didn't get the expected message, throw an exception
            if(!ConfMsg.equals("Correct messages received--Congratulations Server!")){
                throw new RuntimeException("Did not receive the correct message from Client");
            }
        } catch (ClassNotFoundException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                 IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }


        socket.close();
        System.out.println("Server Socket Closed");
    }
}
