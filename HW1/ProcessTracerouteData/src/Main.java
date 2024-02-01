//Elisabeth Frschknecht
//CS 6014 HW 1
//this program reads in the traceroute files produced from the terminal commands, processes the data, and prints the results to files

import java.io.FileNotFoundException;
import java.io.IOException;


public class Main {
    public static void main(String[] args) throws FileNotFoundException {
        // Press Opt+Enter with your caret at the highlighted text to see how
        // IntelliJ IDEA suggests fixing it.
        System.out.println( "Hello and welcome!");
        TraceData data1 = new TraceData("../resources/data.txt");
        TraceData data2 = new TraceData("../resources/data2.txt");
        try{
            data1.PrintData("../Solutions/results1.txt");
            data2.PrintData("../Solutions/results2.txt");
        }catch (IOException e){
            e.printStackTrace();
        }

    }
}