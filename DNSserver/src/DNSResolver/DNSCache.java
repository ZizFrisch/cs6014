package DNSResolver;

//Elisabeth Frischknecht
//CS 6014 DNS Resolver
//February 1, 2024

import java.util.HashMap;

public class DNSCache {
    /**
     * This class is the local cache. It should basically just have a HashMap<DNSQuestion, DNSRecord> in it.
     * You can just store the first answer for any question in the cache (a response for google.com might return 10 IP addresses, just store the first one).
     * This class should have methods for querying and inserting records into the cache.
     * When you look up an entry, if it is too old (its TTL has expired), remove it and return "not found."
     */

    public HashMap<DNSQuestion, DNSRecord> localCache;

    /**
     * empty constructor
     */
    public DNSCache(){
        localCache = new HashMap<>();
    }


    /**
     * this method looks to see if there is a question in the cache. if it is expired, it will remove it from the cache
     * and return null to indicate "not found"
     * @param query
     *      the question we are looking to see if it is included
     * @return
     *      the value of the key-value pair denoted by question/record in the hash map
     *      null if it was not found
     */
    public DNSRecord queryCache(DNSQuestion query){
        System.out.println("---------querying cache---------");
        DNSRecord value = localCache.get(query);

        //if it exists and is expired then remove it
        if(value != null && value.isExpired()){
            localCache.remove(query);
            System.out.println("---------REMOVED FROM CACHE---------");
            return null;

        }

        return value;
    }

    public void insert(DNSQuestion key, DNSRecord value){
        localCache.put(key, value);
        System.out.println("--------------Added to Cache---------");
        System.out.println("size of cache: " + localCache.size());
    }

}
