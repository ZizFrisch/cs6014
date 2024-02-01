//Elisabeth Frischknecht
//CS 6014 HW 1
//this class contains the methods necessary for reading files, processing data, and outputting the results from the traceroute command

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class TraceData {

    public ArrayList<Trace> data_ = new ArrayList<>();
    public ArrayList<String> results_ = new ArrayList<>();

    /**
     * the constructor takes a file and builds the data_ arraylist of the type Trace
     * @param filename
     * @throws FileNotFoundException
     */
    public TraceData(String filename) throws FileNotFoundException{
        File file1 = new File(filename);
        Scanner sc = new Scanner(file1);
        int hop = 0;
        String name = "";
        String address = "";

        while(sc.hasNext()){
            String fullLine = sc.nextLine();
            //limit = 0 – In this case, the pattern will be applied as many times as possible, the resulting array can be of any size, and trailing empty strings will be discarded.
            String[] splitLine = fullLine.split(" ", 0);

            ArrayList<String> strList = new ArrayList<String>(Arrays.asList(splitLine));

            //System.out.println("the split line length is: " + strList.size());
            strList.removeAll(Arrays.asList("", null));
            //System.out.println("after removing, the line length is: " + strList.size());
            //System.out.println(strList);

            name = strList.get(0);
            address = strList.get(1);

            //if the size is 4 or less, then it does not have a new "hop" number. So if it is >4 we'll grab the new hop from the line
            if(strList.size() > 4){
                hop = Integer.parseInt(strList.get(0));
                name = strList.get(1);
                address = strList.get(2);
            }

            ArrayList<Integer> indices = findAllIndices(strList,"ms");
            for(int i = 0; i < indices.size(); i++){
                //get the index in the strList array of the value. we are doing a "-1" because the value we want is one element prior to the "ms"
                int index = indices.get(i) - 1;

                if( !strList.get(index).equals("*") ){
                    //if we received good data (not a *)
                    Trace datapoint = new Trace();
                    datapoint.hop_ = hop;
                    datapoint.delay_ = Double.parseDouble(strList.get(index));
                    datapoint.name_ = name;
                    datapoint.IPAddress_ = address;
                    data_.add(datapoint);
                }
            }


        }

        AnalyzeData(hop);

    }

    /**
     * This is a helper method to find all the indices in an array that contain a given value
     * @param input
     *      the array to check for the input
     * @param value
     *      the value to look for
     * @return
     *      an arrayList of integers that are the indices where the values where found
     */
    private ArrayList<Integer> findAllIndices (ArrayList<String> input, String value){
        ArrayList<Integer> result = new ArrayList<>();
        for(int i = 0; i < input.size(); i++){
            if(input.get(i).equals(value)){
                result.add(i);
            }
        }
        return result;
    }

    /**
     * Prints the data stored in results to a file
     * @param fileName
     *      this is the name of the file to be written to
     * @throws IOException
     */
    public void PrintData(String fileName) throws IOException {
//        for(Trace element: data_){
//            System.out.println("Hop: " + element.hop_ + " Address: " + element.IPAddress_ + " Delay: " + element.delay_);
//        }
//        System.out.println("\n\n Results here");
//        for(String line: results_){
//            System.out.println(line);
//        }

        FileWriter filewrite = new FileWriter(fileName);
        for(String statement: results_){
            try {
                filewrite.write(statement + "\n");
                //filewrite.write("\n");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        filewrite.close(); //close the file when you are done with it
    }

    /**
     * this function computes the average at each hop and builds the results array
     * @param hopMax
     *      essentially the number of hops, but the highest hop order that was found in the constructor
     */
    private void AnalyzeData(int hopMax){

        for(int i = 1; i <= hopMax; i++){
            int numHops = 0;
            double sum = 0;
            String address = "";
            for(Trace element: data_){
                if(element.hop_ == i){
                    sum += element.delay_;
                    numHops ++;
                    address = element.IPAddress_;
                }
                if(numHops >= 3){
                    break;
                }
            }

            double average = sum/numHops;
            results_.add( i + "\t" + address + "\t" + average);
        }

    }


}
