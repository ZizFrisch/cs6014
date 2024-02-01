package DNSResolver;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;

public class DNSServer {

    /**
     * This class should open up a UDP socket (DatagramSocket class in Java), and listen for requests.
     * When it gets one, it should look at all the questions in the request. If there is a valid answer in cache, add that the response, otherwise create another UDP socket to forward the request Google (8.8.8.8) and then await their response.
     * Once you've dealt with all the questions, send the response back to the client.
     *
     * Note: dig sends an additional record in the "additionalRecord" fields with a type of 41.
     * You're supposed to send this record back in the additional record part of your response as well.
     * Note, that in a real server, the UDP packets you receive could be client requests or google responses at any time.
     * For our basic testing you can assume that the next UDP packet you get after forwarding your request to Google will be the response from Google.
     * To be more robust, you can look at the ID in the request, and keep track of your "in-flight" requests to Google, but you don't need to do that for the assignment.
     */

    static DNSCache cache = new DNSCache();
    static ArrayList<DNSRecord> answer = new ArrayList<>();

    public static void main(String[] args){
        try {
            DatagramSocket socket = new DatagramSocket(8053);

            while(true){
                //TODO: WHY IS THIS 1024? IS THAT ALWAYS THE SIZE
                byte[] requestData = new byte[512];
                DatagramPacket requestPacket = new DatagramPacket(requestData, requestData.length);
                socket.receive(requestPacket);

                //turn the request Packet into a DNSMessage and decode it (the message class decodes all pieces)
                DNSMessage requestMessage = DNSMessage.decodeMessage(requestPacket.getData());
                System.out.println("request message decoded");
                System.out.println(requestMessage.toString());

                ArrayList<DNSQuestion> questions = requestMessage.getQuestions_();
                DNSRecord cachedRecord = cache.queryCache(questions.get(0));

                //
                DNSMessage responseMessage = new DNSMessage();
                System.out.println(responseMessage.toString());

                if(cachedRecord != null && !cachedRecord.isExpired()){
                    answer = new ArrayList<>();
                    answer.add(cachedRecord);

                }
                else{
                    //DatagramSocket forwardSocket = new DatagramSocket();
                    InetAddress googleDNS = InetAddress.getByName("8.8.8.8");
                    //why port 53 here?
                    DatagramPacket forwardPacket = new DatagramPacket(requestData,requestData.length,googleDNS, 53);
                    socket.send(forwardPacket);
                    System.out.println("sent packet to google");

                    DatagramPacket responsePacket = new DatagramPacket(requestData,requestData.length);
                    socket.receive(responsePacket);
                    System.out.println("received response from google");

                    responseMessage = DNSMessage.decodeMessage(responsePacket.getData());
                    System.out.println("decoded response from google");

                    answer = responseMessage.getAnswers_();
                    cache.insert(questions.get(0), answer.get(0));
                }

                System.out.println("send back to the user");
                responseMessage = DNSMessage.buildResponse(requestMessage, answer.toArray(new DNSRecord[0]));
                byte[] responseData = responseMessage.toBytes();
                DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length, requestPacket.getAddress(), requestPacket.getPort());
                socket.send(responsePacket);
            }
        }
        catch (IOException e){
            e.printStackTrace();
        }
    }
}

