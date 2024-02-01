//Elisabeth Frischknecht
//CS 6014 HW 1
//this class is a "data point" found in a traceroute file. Although it can contain all the data found in the file,
//I ended up only needing the hop, delay, and IP Address

public class Trace {
    public String name_;
    public String IPAddress_;
    public int hop_;
    public double delay_;

    Trace(){
        name_ = "none";
        IPAddress_ = "none";
        delay_ = 0;
        hop_ = 0;
    }

}
