package DNSResolver;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;


//TODO: SHOULD THESE BE TRY/CATCH BLOCKS OR JUST THROWING EXCEPTIONS
public class DNSMessage {

    /**
     * This corresponds to an entire DNS Message. It should contain:
     *
     * the DNS Header
     * an array of questions
     * an array of answers
     * an array of "authority records" which we'll ignore
     * an array of "additional records" which we'll almost ignore
     * You should also store the the byte array containing the complete message in this class. You'll need it to handle the compression technique described above
     */

    private DNSHeader header_;
    private ArrayList<DNSQuestion> questions_;
    private ArrayList<DNSRecord> answers_;
    private ArrayList<DNSRecord> authorityRecords_;
    private ArrayList<DNSRecord> additionalRecords_;
    private byte[] message_;

//        +---------------------+
//        |        Header       |
//        +---------------------+
//        |       Question      | the question for the name server
//        +---------------------+
//        |        Answer       | RRs answering the question
//        +---------------------+
//        |      Authority      | RRs pointing toward an authority
//        +---------------------+
//        |      Additional     | RRs holding additional information
//        +---------------------+

    public DNSMessage(){
        questions_ = new ArrayList<>();
        answers_ = new ArrayList<>();
        authorityRecords_ = new ArrayList<>();
        additionalRecords_ = new ArrayList<>();
    }

    static DNSMessage decodeMessage(byte[] bytes) throws IOException {
        //call decode message here?

        ByteArrayInputStream myStream = new ByteArrayInputStream(bytes);
        DNSMessage newMessage = new DNSMessage();

        // store the byte array containing the complete message
        newMessage.message_ = Arrays.copyOf(bytes, bytes.length);


        //decode the header
        newMessage.header_ = DNSHeader.decodeHeader(myStream);

        //for the number of questions we have, read in the questions
        short numQuestions = newMessage.header_.getQdcount_();
        for(int i = 0; i < numQuestions; i++){
            newMessage.questions_.add(DNSQuestion.decodeQuestion(myStream,newMessage));
        }

        //for the number of answers we have, read them in
        short numAnswers = newMessage.header_.getAncount_();
        for(int i = 0; i< numAnswers; i++){
            newMessage.answers_.add(DNSRecord.decodeRecord(myStream,newMessage));
        }

        //for the number of authority records we have, read them in
        short numRecords = newMessage.header_.getNscount_();
        for(int i = 0; i < numRecords; i++){
            newMessage.authorityRecords_.add(DNSRecord.decodeRecord(myStream,newMessage));
        }

        //for the number of additional records we have, read them in
        short numAdditional = newMessage.header_.getArcount_();
        for(int i = 0; i < numAdditional; i++){
            newMessage.additionalRecords_.add(DNSRecord.decodeRecord(myStream,newMessage));
        }

        return newMessage;
    }


    /**
     * read the pieces of a domain name starting from the current position of the input stream
     * Went over this with Chunhao and he said this was right
     * @param inputStream
     * @return
     */
    String[] readDomainName(InputStream inputStream) throws IOException {
//        a domain name represented as a sequence of labels, where
//        each label consists of a length octet followed by that
//        number of octets.  The domain name terminates with the
//        zero length octet for the null label of the root.  Note
//        that this field may be an odd number of octets; no
//        padding is used.
        //an octet is 8 bits

        //attach the input stream to a data input stream
        DataInputStream myStream = new DataInputStream(inputStream);

        //read the first label
        byte length = myStream.readByte();

        //if the first byte is 0, indicating an empty name, return an empty array so we avoid writing extra bytes
        if(length == 0){
            return new String[0];
        }

        //make an arraylist of strings
        ArrayList<String> pieces = new ArrayList<>();

        //if it's a non-zero label, we read in the number of octets specified in the label
        while(length != 0){
            byte[] word;
            word = myStream.readNBytes(length);
            //convert the byte to a string
            String str = new String(word, StandardCharsets.UTF_8);
            pieces.add(str);

            //read in the next label
            length = myStream.readByte();
        }

        //create the string array
        return pieces.toArray(new String[0]);
    }

    /**
     * same, but used when there's compression and we need to find the domain from earlier in the message.
     * This method should make a ByteArrayInputStream that starts at the specified byte and call the other version of this method
     * @param firstByte
     * @return
     */
    String[] readDomainName(int firstByte) throws IOException {
        ByteArrayInputStream myStream = new ByteArrayInputStream(message_,firstByte,message_.length - firstByte);
        return readDomainName(myStream);
    }


    /**
     * build a response based on the request and the answers you intend to send back.
     * @param request
     * @param answers
     * @return
     */
    static DNSMessage buildResponse(DNSMessage request, DNSRecord[] answers){

        DNSMessage response = new DNSMessage();

        response.answers_ = new ArrayList<>(Arrays.asList(answers));
        response.header_ = DNSHeader.buildHeaderForResponse(request,response);
        response.questions_ = request.questions_;

        response.authorityRecords_ = request.authorityRecords_;
        response.additionalRecords_ = request.additionalRecords_;

        return response;
    }

    /**
     * get the bytes to put in a packet and send back
     * @return
     */
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream myStream = new ByteArrayOutputStream();
        HashMap<String,Integer> map = new HashMap<>();

        //write header
        header_.writeBytes(myStream);

        //write questions
        for(DNSQuestion question : questions_){
            question.writeBytes(myStream, map);
        }

        //write answers
        answers_.get(0).writeBytes(myStream, map);
//        for(DNSRecord answer: answers_){
//            answer.writeBytes(myStream, map);
//        }

        //write authority records
        for(DNSRecord authority : authorityRecords_){
            authority.writeBytes(myStream, map);
        }

        //write additional records
        for(DNSRecord record : additionalRecords_){
            record.writeBytes(myStream, map);
        }

        return myStream.toByteArray();
    }


    /**
     * If this is the first time we've seen this domain name in the packet, write it using the DNS encoding
     * (each segment of the domain prefixed with its length, 0 at the end), and add it to the hash map.
     * Otherwise, write a back pointer to where the domain has been seen previously.
     * @param outputStream
     * @param map
     * @param domainPieces
     */
    static void writeDomainName(ByteArrayOutputStream outputStream, HashMap<String,Integer> map, String[] domainPieces) throws IOException {
        DataOutputStream myStream = new DataOutputStream(outputStream);

        String domainName = DNSMessage.joinDomainName(domainPieces);
        if(map.containsKey(domainName)){
            //if it's contained, then we write back a pointer to where it has been seen previously
            //the integer in the hashmap is the pointer
            //the index of where it is being stored in the response message
            //write the compression thing

            int pointer = map.get(domainName);
            pointer |= (0xC000);

            myStream.writeShort (pointer);
        }
        else{
            //add to the hashmap
            Integer location = outputStream.size();
            map.put(domainName,location);

            for (String domainPiece : domainPieces) {
                //writebytes? with a data output stream?
                myStream.writeByte(domainPiece.length());
                myStream.writeBytes(domainPiece);
//                outputStream.write(domainPiece.length());
//                outputStream.write(domainPiece.getBytes());
            }
            //write a zero at the end as an end character
            myStream.writeByte(0);
        }
    }


    /**
     *join the pieces of a domain name with dots ([ "utah", "edu"] -> "utah.edu" )
     * @param pieces
     *      this is an array of strings containing each individual part of the domain name
     * @return
     *      the domain name as one string
     */
    static String joinDomainName(String[] pieces){
        StringBuilder result = new StringBuilder();
        for(int i = 0; i < pieces.length; i++){
            if(i < pieces.length -1){
                result.append(pieces[i]).append(".");
            }
            else{
                result.append(pieces[i]);
            }
        }

//        for(String piece : pieces){
//            result.append(piece).append(".");
//        }

        //TODO: GET RID OF THIS LOOP
        //string.join(".", pieces);
        return result.toString();
    }

    /**
     * the getter for the header of the message
     * @return
     *      returns the header portion of this class
     */
    public DNSHeader getHeader (){
        return header_;
    }

    public int getNumAnswers(){
        return answers_.size();
    }

    public ArrayList<DNSQuestion> getQuestions_(){
        return questions_;
    }

    public ArrayList<DNSRecord> getAnswers_(){
        return answers_;
    }

    @Override
    public String toString(){
       return super.toString();
    }

}
