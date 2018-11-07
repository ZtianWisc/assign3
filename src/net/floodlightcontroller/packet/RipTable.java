package net.floodlightcontroller.packet;

import java.util.LinkedList;
import java.util.List;

public class RipTable {
    private List<RIPv2Entry> entries;

    public RipTable(){
        this.entries = new LinkedList<>();
    }

    public void insert(RIPv2Entry entry){
        synchronized (this.entries){
            this.entries.add(entry);
        }
    }
    /** find entry by address and subnetMask, if not found, add; else update */
    public void update(RIPv2Entry entry) {
        synchronized(this.entries)
        {
            int address = entry.getAddress();
            int subnetMask = entry.getSubnetMask();
            RIPv2Entry oldEntry = this.find(address, subnetMask);
            if (null == oldEntry) {
                this.entries.add(entry);
            }
            else{
                int oldMetric = oldEntry.getMetric();
                if (oldMetric < entry.getMetric()) {
                    this.entries.remove(oldEntry);
                    this.entries.add(entry);
                }
            }
        }
    }
    /** find entry by address and subnetMask, also timeout entry after 30 seconds */
    public RIPv2Entry find(int address, int subnetMask) {
        synchronized(this.entries)
        {
            for (RIPv2Entry entry : this.entries)
            {
                if (System.currentTimeMillis() - entry.getTimeStamp() > 30 * 1000) {
                    this.entries.remove(entry);
                    continue;
                }
                if ((entry.getAddress() == address) && (entry.getSubnetMask() == subnetMask))
                { return entry; }
            }
        }
        return null;
    }

    public List<RIPv2Entry> getAllEntries(){ return this.entries; }

    public String toString()
    {
        synchronized(this.entries)
        {
            if (0 == this.entries.size())
            { return " WARNING: route table empty"; }

            String result = "Destination\t\tMask\t\tmetric\n";
            for (RIPv2Entry entry : this.entries)
            { result += entry.toString()+"\n"; }
            return result;
        }
    }
}
