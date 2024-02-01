//this class contains the methods necessary for reading, processing, and writing ping files
//Elisabeth Frischknecht
//CS 6014 HW1

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

public class PingData {

    public ArrayList<Double> data_ = new ArrayList<>();
    public ArrayList<String> results_ = new ArrayList<>();
    private double average_ = 0;
    private double averageQueingDelay = 0;

    public PingData(String filename) throws FileNotFoundException{
        File file1 = new File(filename);
        Scanner sc = new Scanner(file1);
        String firstLine = "";
        firstLine = sc.nextLine();

        while(sc.hasNext()){
            String fullLine = sc.nextLine();
            String[] splitLine = fullLine.split(" ", 0);
            //System.out.println("size: " + splitLine.length);

            if(splitLine.length == 8){
                data_.add(Double.parseDouble(splitLine[6].substring(5)));
            }
        }
        AnalyzeData();
    }

    private void AnalyzeData(){
        double sum = 0;
        double adjustedSum = 0;

        double queingDelay = data_.get(0);

        //sum up the values for the average
        for(Double point: data_){
            sum += point;

            //find the smallest delay, and let this be the queing delay
            if(point < queingDelay){
                queingDelay = point;
            }
        }

        //calculate the adjusted
        for(Double point: data_){
            adjustedSum += point - queingDelay;
        }

        average_ = sum/data_.size();
        averageQueingDelay = adjustedSum/data_.size();
    }

    public void PrintResults(String fileName) throws IOException {
        FileWriter filewrite = new FileWriter(fileName);

        try {
            filewrite.write( "total average delay: " + average_ + " ms\n");
            filewrite.write("average queuing delay: " + averageQueingDelay + " ms\n");
            //filewrite.write("\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        filewrite.close();
    }
}
