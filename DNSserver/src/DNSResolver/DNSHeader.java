package DNSResolver;
import java.io.*;


//This class should store all the data provided by the 12 byte DNS header. See the spec for all the fields needed.
//include getters, but NO setters
//test that you can read/decode the header before starting other classes
public class DNSHeader {
    private short id_;
    private short flags_;
    private int qr_;
    private int opcode_;
    private int aa_;
    private int tc_;
    private int rd_;
    private int ra_;
    private int z_;
    private int ad_;
    private int cd_;
    private int rcode_;
    private short qdcount_;
    private short ancount_;
    private short nscount_;
    private short arcount_;

    //DNS Headers have the following format:

//                                            1  1  1  1  1  1
//              0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//            |                      ID                       |
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//            |QR|   OpCode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//            |                QDCOUNT/ZOCOUNT                |
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//            |                ANCOUNT/PRCOUNT                |
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//            |                NSCOUNT/UPCOUNT                |
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//            |                    ARCOUNT                    |
//            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+



    public DNSHeader(){
//        DNSHeader header = new DNSHeader();
        //initialize flags to 0 when created
        flags_ = 0;
    }

    /**
     * Read the header from an input stream (we'll use a ByteArrayInputStream but we will only use the basic read methods of input stream to read 1 byte, or to fill in a byte array, so we'll be generic).
     * @return
     */
    static DNSHeader decodeHeader(InputStream inStream) throws IOException {
        DataInputStream bytestream = new DataInputStream(inStream);
        DNSHeader header = new DNSHeader();

        //read all of the lines in from the header
        //DNS header is 12 bytes--each line has 2 bytes and will be read in as a short
        // ID: 16 bits make up the ID (USE READ SHORT)
        header.id_ = bytestream.readShort();
        //this is the second line of the header, which contains all of the flags necessary
        header.flags_ = bytestream.readShort();
        //QDCOUNT --> unsigned specifying number of entries - 16 bits (read short)
        header.qdcount_ = bytestream.readShort();
        //ANCOUNT --> unsigned specifying number of resource records - 16 bits (read short)
        header.ancount_ = bytestream.readShort();
        //NSCOUNT --> unsigned specifying number of name of server resource records - 16 bits (read short)
        header.nscount_ = bytestream.readShort();
        //ARCOUNT --> unsigned specifying number of resource records in the additional records section - 16 bits (read short)
        header.arcount_ = bytestream.readShort();

        //parse the flags_ for all of the other pieces of the header
        // QR: one bit --> whether a query or response
        // 1000 0000 0000 0000
        header.qr_ = (header.flags_ & 0x8000)>>15;

        // OPCODE: 4 bits --> specifies type of query
        // 0111 1000 0000 0000
        header.opcode_ = (header.flags_ & 0x7800)>>11;
        // AA (Authoritative Answer) --> one bit is valid in responses
        // 0000 0100 0000 0000
        header.aa_ = (header.flags_ & 0x0400)>>10;
        //TC (TrunCation) --> specifies that this message was truncated due to being too long
        // 0000 0010 0000 0000
        header.tc_ = (header.flags_ & 0x0200)>>9;
        //RD (Recursion Desired --> one bit
        //0000 0001 0000 0000
        header.rd_ = (header.flags_ & 0x0100)>>8;
        // RA Recursion available --> one bit
        //0000 0000 1000 0000
        header.ra_ = (header.flags_ & 0x0080)>>7;
        // Z --> must be 0 in all one bit
        //0000 0000 0100 0000
        header.z_ = (header.flags_ & 0x0040)>>6;
        //AD is "authentic data" and will largely be ignored here, but will be copied in build HeaderForResponse
        //0000 0000 0010 0000
        header.ad_ = (header.flags_ & 0x0020)>>5;
        //CD is "checking disabled" and will largely be ignored here, but will be copied in buildHeaderForResponse
        //0000 0000 0001 0000
        header.cd_ = (header.flags_ & 0x0010)>>4;
        // RCODE --> 4 bit field
        //0000 0000 0000 1111
        header.rcode_ = header.flags_ & 0x000F;

        System.out.println("printing header values:");
        int temp = (int)header.id_;
        System.out.println("ID: " + Integer.toHexString(temp & 0xFFFF));
        temp = header.flags_;
        System.out.println("FLAGS: " + Integer.toHexString(temp&0xFFFF));
        System.out.println("QUESTIONS: " + header.qdcount_);
        System.out.println("Answer RRs: " + header.ancount_);
        System.out.println("Authority RRs: " + header.nscount_);
        System.out.println("Additional RRs: " + header.arcount_);



        return header;
    }

    /**
     * This will create the header for the response. It will copy some fields from the request
     * @param request
     * @param response
     * @return
     */
    static DNSHeader buildHeaderForResponse(DNSMessage request, DNSMessage response){
        //DNSHeader headerResponse = new DNSHeader();
        DNSHeader headerResponse = request.getHeader();


        //TODO: GET NUMBER OF ANSWERS FROM RESPONSE (matt)
        //headerResponse.ancount_ = (short)response.getNumAnswers();
        headerResponse.ancount_ = 1;
        headerResponse.qr_ = 1;

        return headerResponse;
    }

    /**
     * write all the bytes from the header to a given output stream
     * @param outStream
     *      the stream that we will be writing the binary to
     * @throws IOException
     */
    void writeBytes(OutputStream outStream) throws IOException {
        DataOutputStream bytestream = new DataOutputStream(outStream);

        //build the flags line
        //parse the flags_ for all of the other pieces of the header
        // QR: one bit --> whether a query or response
        // 1000 0000 0000 0000
        flags_ |= (short) (qr_ << 15);

        // OPCODE: 4 bits --> specifies type of query
        // 0111 1000 0000 0000
        flags_ |= (short) (opcode_ << 11);

        // AA (Authoritative Answer) --> one bit is valid in responses
        // 0000 0100 0000 0000
        flags_ |= (short)(aa_ << 10);

        //TC (TrunCation) --> specifies that this message was truncated due to being too long
        // 0000 0010 0000 0000
        flags_ |= (short)(tc_<<9);

        //RD (Recursion Desired --> one bit
        //0000 0001 0000 0000
        flags_ |= (short)(rd_ << 8);

        // RA Recursion available --> one bit
        //0000 0000 1000 0000
        flags_ |= (short)(ra_ << 7);

        // Z --> must be 0 in all one bit
        //0000 0000 0100 0000
        flags_ |= (short)(z_<<6);

        //AD is "authentic data" and will largely be ignored here, but will be copied in build HeaderForResponse
        //0000 0000 0010 0000
        flags_ |= (short)(z_<<5);

        //CD is "checking disabled" and will largely be ignored here, but will be copied in buildHeaderForResponse
        //0000 0000 0001 0000
        flags_ |= (short)(z_<<4);

        // RCODE --> 4 bit field
        //0000 0000 0000 1111
        flags_ |= (short)(rcode_);


        //write all the bytes to the output stream

        bytestream.writeShort(id_);
        bytestream.writeShort(flags_);
        bytestream.writeShort(qdcount_);
        bytestream.writeShort(ancount_);
        bytestream.writeShort(nscount_);
        bytestream.writeShort(arcount_);
    }

    /**
     *
     * @return humanly readable string version of a header object - reasonable implementation can be autogenerated from this IDE!
     */
    @Override
    public String toString(){

        //TODO: see what this prints, adjust as needed
        return super.toString();
    }

    public short getQdcount_(){
        return qdcount_;
    }

    public short getAncount_(){
        return ancount_;
    }

    public short getNscount_(){
        return nscount_;
    }

    public short getArcount_(){
        return arcount_;
    }


}
