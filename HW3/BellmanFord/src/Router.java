import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Router {

    private HashMap<Router, Integer> distances;
    private String name;
    public Router(String name) {
        this.distances = new HashMap<>();
        this.name = name;
    }

    public void onInit() throws InterruptedException {
		//As soon as the network is online,
		//fill in your initial distance table and broadcast it to your neighbors

        HashSet<Neighbor> neighbors =  Network.getNeighbors(this);
        Set<Router> routers = Network.getRouters();

        //set all the routers to infinite cost
        for(Router router : routers){
            if(router.equals(this)){
                this.distances.put(router,0);
                //System.out.println("added router" + router.toString() + 0);
            }
            else{
                this.distances.put(router, Integer.MAX_VALUE);
                //System.out.println("added router" + router.toString() + Integer.MAX_VALUE);
            }

        }

       // if it is a neighbor, update the cost to be better
        for(Neighbor neighbor : neighbors){
            this.distances.put(neighbor.router, neighbor.cost);
            //System.out.println("updated neighbor" + neighbor.router.toString() + neighbor.cost);
        }

        //after it's made, broadcast the table to the neighbors

        for(Neighbor neighbor: neighbors){
            Message send = new Message(this, neighbor.router, this.distances);
            Network.sendDistanceMessage(send);
        }

        //System.out.println("neighbor size" + distances.size());

    }

    //update your distance table and broadcast it to your neighbors if it changed
    public void onDistanceMessage(Message message) throws InterruptedException {
        //System.out.println("RECEIVED DISTANCE MESSAGE");

        //update distance table
        //sender //receiver //distances
        boolean changed = false;
        Router sender = message.sender;
        Router receiver = message.receiver;
        HashMap<Router, Integer> receivedTable = message.distances;

        //if their table shows infinity do nothing
        //compare the distance I have stored to the sender + the distance from the sender to the "destination" is
        //less than the current distance I have listed to the sender, replace it
        Integer distance_to_sender = this.distances.get(sender);
        for(Map.Entry<Router, Integer> entry: receivedTable.entrySet() ){

            Integer sender_to_destination = entry.getValue();
            Integer currentDistance = this.distances.get(entry.getKey());

            if(distance_to_sender != Integer.MAX_VALUE && sender_to_destination != Integer.MAX_VALUE && distance_to_sender + sender_to_destination < currentDistance ){
                this.distances.put(entry.getKey(), distance_to_sender + sender_to_destination);
                changed = true;
                //System.out.println("changed value");
            }
        }
        //broadcast it to your neighbors if it changed
        if(changed){
            for(Neighbor neighbor: Network.getNeighbors(this)){
                Message send = new Message(this, neighbor.router, this.distances);
                Network.sendDistanceMessage(send);
            }
        }

    }


    public void dumpDistanceTable() {
        System.out.println("router: " + this);
        for(Router r : distances.keySet()){
            System.out.println("\t" + r + "\t" + distances.get(r));
        }
    }

    @Override
    public String toString(){
        return "Router: " + name;
    }
}
