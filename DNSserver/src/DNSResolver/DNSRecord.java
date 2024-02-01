package DNSResolver;

import java.io.*;
import java.util.Date;
import java.util.HashMap;

public class DNSRecord {
   // Everything after the header and question parts of the DNS message are stored as records.
    // This should have all the fields listed in the spec as well as a Date object storing when this record was created by your program.
    // It should also have the following public methods:
    private String[] domainName_;
    private short type_;
    private short class_;
    private int ttl_;
    private short rdLength_;
    private byte[] rdata_;
    private Date creationDate_;

    /**
     * empty constructor
     */
    public DNSRecord(){

    }

    /**
     * GOT THE MARK/RESET BIT FROM CHUNHAO
     * @param inputStream
     * @param message
     * @return
     * @throws IOException
     */
    public static DNSRecord decodeRecord(InputStream inputStream, DNSMessage message) throws IOException {
        //USE MARK AND RESET TO READ A COMPRESSION AND GO BACK
        DNSRecord record = new DNSRecord();
        record.creationDate_ = new Date();
        DataInputStream myStream = new DataInputStream(inputStream);

        //mark the position of the current pointer so we can reset this later if needed
        myStream.mark(2);
        short compress = myStream.readShort();

        //0xC000 is 1100 0000
        boolean compressFlag = ( (compress & 0xC000) ==0xC000);

        if(compressFlag){//compression condition
            //compress ^= (byte) 0xC0;
            compress &= (short) 0x3FFF;
            record.domainName_ = message.readDomainName(compress);
        }
        else{
            //reset our place in the input stream, since we read in the first 2 bytes
            myStream.reset();
            record.domainName_ = message.readDomainName(inputStream);
        }

        record.type_ = myStream.readShort();
        record.class_ = myStream.readShort();
        record.ttl_ = myStream.readInt();
        record.rdLength_ = myStream.readShort();
        record.rdata_ = myStream.readNBytes(record.rdLength_);

        return record;
    }

    public void writeBytes(ByteArrayOutputStream outputStream, HashMap<String,Integer> map) throws IOException {
        //write domain name, call from message class
        DNSMessage.writeDomainName(outputStream, map, domainName_);

        DataOutputStream myStream = new DataOutputStream(outputStream);
        myStream.writeShort(type_);
        myStream.writeShort(class_);
        myStream.writeInt(ttl_);
        myStream.writeShort(rdLength_);
        myStream.write(rdata_);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    /**
     * return whether the creation date + the time to live is after the current time. The Date and Calendar classes will be useful for this.
     * @return
     */
    boolean isExpired(){
        //ttl is time to live in seconds, convert to miliseconds
        int ttl_miliseconds = ttl_ * 1000;
        Date currentTime = new Date();

        return (currentTime.getTime() - creationDate_.getTime() > ttl_miliseconds );
    }
}
