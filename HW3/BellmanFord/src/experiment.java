public class experiment {

    public static void main(String[] args) throws InterruptedException {

        int sample_size = 20;
        int[] data = new int[sample_size];
//        Network.makeSimpleNetwork(); //use this for testing/debugging
        for(int i = 0; i < sample_size; i++){
            Network.makeProbablisticNetwork(10); //use this for the plotting part
            Network.dump();

            Network.startup();
            Network.runBellmanFord();

            System.out.println("done building tables!");
            for(Router r : Network.getRouters()){
                r.dumpDistanceTable();
            }
            System.out.println("total messages: " + Network.getMessageCount());
            data[i] = Network.getMessageCount();
        }

        System.out.println("final data: ");
        int sum = 0;
        for(int i = 0; i< sample_size; i++){
            System.out.println(data[i]);
            sum += data[i];
        }
        System.out.println("average: ");
        System.out.println(sum/sample_size);




    }
}
