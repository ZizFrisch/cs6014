//Elisabeth Frischknecht
//CS 6014 DNS Resolver
//February 1, 2024

package DNSResolver;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

public class DNSQuestion {
    String[] domainName_;
    short qType_;
    short qClass_;

    /**
     * empty constructor
     */
    DNSQuestion(){

    }

    /**
     * Read a question from the input stream.
     * Due to compression, you may have to ask the DNSMessage containing this question to read some of the fields.
     */
    static DNSQuestion decodeQuestion(InputStream inputStream, DNSMessage message) throws IOException {
        DNSQuestion question = new DNSQuestion();

        question.domainName_ = message.readDomainName(inputStream);

        //get the Q type
        DataInputStream myStream = new DataInputStream(inputStream);
        question.qType_ = myStream.readShort();

        //get the QClass
        question.qClass_ = myStream.readShort();


        //this block of code prints the parts of the question we receive
//        System.out.println("**********************************");
//        System.out.println("Printing Question: ");
//        System.out.println("domain name: " + DNSMessage.joinDomainName(question.domainName_));
//        int temp = question.qType_;
//        System.out.println("Type: " + Integer.toHexString(temp & 0xFFFF));
//        temp = question.qClass_;
//        System.out.println("Class: " + Integer.toHexString(temp & 0xFFFF));

        return question;
    }

    /**
     * Write the question bytes which will be sent to the client.
     * The hash map is used for us to compress the message, see the DNSMessage class below.
     * @param outStream
     *      the stream that we will be writing bytes to
     * @param map
     *      holds the domain names we have already seen for the questions and records classes
     */
    void writeBytes(ByteArrayOutputStream outStream, HashMap<String,Integer> map) throws IOException {
        DNSMessage.writeDomainName(outStream, map, domainName_);

        DataOutputStream myStream = new DataOutputStream(outStream);
        myStream.writeShort(qType_);
        myStream.writeShort(qClass_);
    }

//let following functions be taken care of by IDE
//    @Override
//    public String toString(){
//        return super.toString();
//    }

    @Override
    public String toString() {
        return "DNSQuestion{" +
                "domainName_=" + Arrays.toString(domainName_) +
                ", qType_=" + qType_ +
                ", qClass_=" + qClass_ +
                '}';
    }

//    @Override
//    public boolean equals(Object obj) {
//       // return this.hashCode() == obj.hashCode();
////        if(!(obj instanceof DNSQuestion)){
////            return false;
////        }
////
////        DNSQuestion otherQuestion = (DNSQuestion) obj;
////
////        return (Arrays.equals(domainName_, otherQuestion.domainName_) && qType_ == otherQuestion.qType_ && qClass_ == otherQuestion.qClass_);
//        if (this == obj){
//            return true;
//        }
//        if (this.getClass() != obj.getClass()){
//            return false;
//        }
//        DNSQuestion question = (DNSQuestion) obj;
//        if (this.qClass_ != question.qClass_){
//            return false;
//        }
//        if (this.qType_ != question.qType_){
//            return false;
//        }
//        return Arrays.equals(this.domainName_, question.domainName_);
//    }

//    @Override
//    public int hashCode() {
//        return super.hashCode();
//    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DNSQuestion that = (DNSQuestion) o;
        return qType_ == that.qType_ && qClass_ == that.qClass_ && Arrays.equals(domainName_, that.domainName_);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(qType_, qClass_);
        result = 31 * result + Arrays.hashCode(domainName_);
        return result;
    }
}
