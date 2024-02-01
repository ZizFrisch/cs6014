import java.io.IOException;

//Elisabeth Frischknecht
//CS 6014 HW 1
//This program reads in files produced by the ping terminal command,
// analyzes them, and then outputs the results to a file


public class Main {
    public static void main(String[] args) {
        // Press Opt+Enter with your caret at the highlighted text to see how
        // IntelliJ IDEA suggests fixing it.
        System.out.printf("Hello and welcome!");

        try{
            PingData data1 = new PingData("../resources/pingdata.txt");
            data1.PrintResults("../Solutions/pingdataResults.txt");
        }catch(IOException e){
            e.printStackTrace();
        }

    }
}