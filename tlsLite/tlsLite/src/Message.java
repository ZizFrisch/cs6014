/*
 * Elisabeth Frischknecht
 * CS6014 TLSLite assignment
 * MSD program March 28, 2024
 *
 * This class handles a lot of the functionality of the actual messaging between the server and the client.
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class Message {


    /**
     * this method concatenates two byte arrays.
     * @param a
     *      the first array to be concatenated
     * @param b
     *      the second array to be concatenated
     * @return
     *      the concatenated array
     */
    public static byte[] concatenate(byte[] a, byte[] b) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(a);
            outputStream.write(b);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

    /**
     * this method concatenates all the byte[] found in an arrayList of byte[]
     * @param messages
     *      the arraylist containing all the byte[]
     * @return
     *      the concatenated byte[]
     */
    public static byte[] concatenate(ArrayList<byte[]> messages) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            for(byte[] message : messages){
                outputStream.write(message);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

    /**
     * generates a hash/hmac from a given byte[]
     * @param secretKey
     *      the key used to build the hash
     * @param message
     *      the message to be hashed
     * @return
     *      a 32 bit hmac hash
     */
    public static byte[] getHMACHash(SecretKey secretKey, byte[] message){
        byte[] hmac256;
        try{
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            hmac256 = mac.doFinal(message);
            return hmac256;
        }catch(Exception e){
            throw new RuntimeException("Failed to generate HMACSHA256 encrypt ");
        }
    }


    /**
     * This is used to send messages. It both encrypts using AES and sends the message with its appropriate hash
     * @param message
     *      the message to be sent
     * @param MAC
     *      the mac used in hashing
     * @param encryptionArray
     *      the key used to encrypt the data
     * @param IV
     *      the initialization vector for AES encryption
     * @param objectOutputStream
     *      the stream to send the message on
     * @param messageHistory
     *      the history of the caller (server/client)
     * @throws IOException
     */
    public static void encryptAndSendMessage(byte[] message, SecretKey MAC, byte[] encryptionArray, IvParameterSpec IV, ObjectOutputStream objectOutputStream, ArrayList<byte[]> messageHistory) throws IOException {
        // To send a message:
        // Compute the HMAC of the message using the appropriate MAC key
        // Use the cipher object to encrypt the message data concatenated with the MAC
        // Send/receive the resulting byte array using the ObjectOutputStream/ObjectIntputStream classes
        // (it will include the array size, etc automatically). You'll want to use the readObject/writeObject methods.
        // For encryption, we'll use AES 128 in CBC mode. For MAC, we'll use HMAC using SHA-256 as our hash function.

        // hash all the history for verification
        byte[] historyHash = Message.concatenate(messageHistory);

        // make a hash of the message
        byte[] HMAC = getHMACHash(MAC, historyHash);
        // concat the messages with the hash
        byte[] messageWithHash = concatenate(message, HMAC);

        // encrypt the messages with the key
        byte[] encMessageWithHash;
        try{
            encMessageWithHash = Encryption.encryptWithAES(messageWithHash, encryptionArray, IV);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //send messages and add them to history
        objectOutputStream.writeObject(encMessageWithHash);
        messageHistory.add(encMessageWithHash);
    }

    /**
     * Receives a message (byte[]) from a stream
     * @param objectInputStream
     *      the stream we are reading from
     * @param messageHistory
     *      the message history to add the received message to
     * @return
     *      the received message as a byte[]
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static byte[] receiveMessage(ObjectInputStream objectInputStream, ArrayList<byte[]> messageHistory) throws IOException, ClassNotFoundException {
        // Client sends HMAC of all handshake messages (including server's HMAC) using its MAC key.
        byte[] receivedMessage;
        Object obj;
        obj = objectInputStream.readObject();
        if (obj instanceof byte[]) {
            // Cast the object to byte[]
            receivedMessage = (byte[]) obj;
        } else {
            // Handle the case where the received object is not a byte[]
            throw new RuntimeException("Received message is not a byte[]");
        }
        messageHistory.add(receivedMessage);
        return receivedMessage;
    }

    /**
     * This method verifies the received messaged by checking the hash against its own computed hash
     * @param MAC
     *      used to create the hmac
     * @param decryptedMessage
     *      the message that was previously received and decrypted
     * @param messageHistory
     *      the full message history of the caller, used for calculating the hmac
     * @return
     *      the isolated message payload, without the hmac on the end
     */
    public static byte[] checkMessage(SecretKey MAC, byte[] decryptedMessage, ArrayList<byte[]> messageHistory){
        // hash length is 32 bytes, so remove that
        byte[] isolatedMessage = Arrays.copyOf(decryptedMessage, decryptedMessage.length-32);
        // isolate the hash
        byte[] receivedHash = new byte[32];
        System.arraycopy(decryptedMessage, decryptedMessage.length-32, receivedHash, 0, 32);

        // calculates the hash of messages received so far to verify the hash. We should not include *this* message as that will be hashed
        // so that message is removed temporarily
        byte[] LastMessage = messageHistory.removeLast();
        byte[] expectedMessages = Message.concatenate(messageHistory);
        byte[] expectedHash = Message.getHMACHash(MAC, expectedMessages);
        // re-add the last message received
        messageHistory.add(LastMessage);

        //check that the hashes are equivalent
        if(!Arrays.equals(expectedHash, receivedHash)){
            System.out.println("expected hash: " + Arrays.toString(expectedHash));
            System.out.println("received hash: " + Arrays.toString(receivedHash));
            throw new RuntimeException("Hashes are not equal");
        }

        return isolatedMessage;
    }

}
