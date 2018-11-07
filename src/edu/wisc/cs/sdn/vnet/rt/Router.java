package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** RIP table for the router */
	private RipTable ripTable;
	private Timer t = new Timer();
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** ARP Queue for the router */
	// maintain a separate queue of packets for each IP address for
	// which we are waiting for the corresponding MAC address.
	private HashMap<Integer, LinkedList<PacketInterfacePair>> arpQueue;

	private static final byte[] BROADCAST = new byte[6];
	private static final String UDP_IP = "224.0.0.9";
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpQueue = new HashMap<>();
		Arrays.fill(BROADCAST, (byte) 0xFF);
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() { return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/** When no routeTableFile is provided, this function initialize
	 *  a new RouteTable and a RIP table */
	public void initializeTables(){
		this.ripTable = new RipTable();
		for (Iface iface : this.interfaces.values()) {
			int subnetMask = iface.getSubnetMask();
			int destinationIp = iface.getIpAddress() & subnetMask;
			this.routeTable.insert(destinationIp, 0, subnetMask, iface);
			RIPv2Entry ripEntry = new RIPv2Entry(destinationIp, subnetMask, 0, System.currentTimeMillis());
			ripEntry.setNextHopAddress(iface.getIpAddress());
			this.ripTable.insert(ripEntry);

			System.out.println("Initialized route table, no static route table provided");
			System.out.println("-------------------------------------------------");
			System.out.print(this.routeTable.toString());
			System.out.println("-------------------------------------------------");

			System.out.println("Initialized RIP table, no static route table provided");
			System.out.println("-------------------------------------------------");
			System.out.print(this.ripTable.toString());
			System.out.println("-------------------------------------------------");
		}
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		short protocol = etherPacket.getEtherType();
		switch(protocol) {
		case Ethernet.TYPE_IPv4:
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
				UDP udp = (UDP)ipPacket.getPayload();
				if (udp.getDestinationPort() == UDP.RIP_PORT && udp.getSourcePort() == UDP.RIP_PORT){
					this.handleRipPacket(etherPacket, inIface);
				}
			}
			else {
				this.handleIpPacket(etherPacket, inIface);
			}
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		/********************************************************************/
	}

	/** This function handles IP packet, if error, send ICMP packet */
	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");
        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl()) {
        	// Time exceeded
			System.out.println("Generating time exceeded ICMP");
			this.send_ICMP_error(etherPacket, inIface, (byte)11, (byte)0, false);
        	return;
        }
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values()) {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
        		System.out.println("Generating destination port unreachable ICMP");
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
					this.send_ICMP_error(etherPacket, inIface, (byte)3, (byte)3, false);
				}
				else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmp = (ICMP) ipPacket.getPayload();
					if (icmp.getIcmpType() == 8){
						this.send_ICMP_error(etherPacket, inIface, (byte)0, (byte)0, true);
					}
				}
				return;
        	}
        }
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

	/** This function forwards IP packet, if error, send ICMP packet */
    private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();
        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
        // If no entry matched, do nothing
        if (null == bestMatch)
        {
        	System.out.println("Generating destination net unreachable ICMP");
        	this.send_ICMP_error(etherPacket, inIface, (byte)3, (byte)0, false);
        	return;
        }
        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface) { return; }
        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }
        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
			if (!arpQueue.containsKey(nextHop)) {
				arpQueue.put(nextHop, new LinkedList<PacketInterfacePair>());
			}
			arpQueue.get(nextHop).add(new PacketInterfacePair(etherPacket, inIface, outIface));
			// send ARP request
			for (int i = 0; i < 3; i++){
				this.sendArpRequest(nextHop, inIface);
				try{
					Thread.sleep(1000);
				}
				catch(InterruptedException exception){
					Thread.currentThread().interrupt();
				}
				arpEntry = this.arpCache.lookup(nextHop);
				if (arpEntry != null){
					// got ARP reply, handleArpPacket() function will take care of it.
					return;
				}
			}
			// received no ARP reply, drop all packets with targetIp waiting in arpQueue
			for (PacketInterfacePair pair : arpQueue.get(nextHop)){
				Ethernet packet = pair.packet;
				Iface initalInIface = pair.inIface;
				this.send_ICMP_error(packet, initalInIface, (byte)3, (byte)1, false);
			}
			arpQueue.remove(nextHop);
			return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        this.sendPacket(etherPacket, outIface);
    }

    /** This function sends ARP request */
    private void sendArpRequest(int targetIp, Iface inIface){
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(BROADCAST);
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength(((byte)Ethernet.DATALAYER_ADDRESS_LENGTH));
		arp.setProtocolAddressLength((byte)4);
		arp.setOpCode(ARP.OP_REQUEST);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		byte[] targetHardwareAddress = new byte[6];
		Arrays.fill(targetHardwareAddress, (byte)0);
		arp.setTargetHardwareAddress(targetHardwareAddress);
		arp.setTargetProtocolAddress(targetIp);
		ether.setPayload(arp);
		this.sendPacket(ether, inIface);
	}

	/** This function sends RIP request
	 *  Won't be called if static routeTable is provided */
	private void sendRipPacket(Ethernet etherPacket, Iface inIface, boolean broadcast, boolean request){
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		IPv4 iPv4 = new IPv4();
		iPv4.setProtocol(IPv4.PROTOCOL_UDP);
		iPv4.setTtl((byte)64);
		iPv4.setVersion((byte)4);
		ether.setPayload(iPv4);
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		iPv4.setPayload(udp);
		ether.setDestinationMACAddress(broadcast ? BROADCAST : etherPacket.getSourceMACAddress());
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		iPv4.setSourceAddress(inIface.getIpAddress());
		if(broadcast){
			iPv4.setDestinationAddress(UDP_IP);
		}
		else{
			IPv4 ip = (IPv4)etherPacket.getPayload();
			iPv4.setDestinationAddress(ip.getSourceAddress());
		}
		RIPv2 rip = new RIPv2();
		udp.setPayload(rip);
		rip.setCommand(request ? RIPv2.COMMAND_REQUEST : RIPv2.COMMAND_RESPONSE);
		for (RIPv2Entry entry : ripTable.getAllEntries()){
			rip.addEntry(entry);
		}
		this.sendPacket(ether, inIface);
	}

	/** This function handles RIP packet
	 *  Won't be called if static routeTable is provided */
	private void handleRipPacket(Ethernet etherPacket, Iface inIface){
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4){ return; }
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP){ return; }
		UDP udpPacket = (UDP)ipPacket.getPayload();
		// Verify IP checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }
		// Verify UDP checksum
		short orignUdpCksum = udpPacket.getChecksum();
		udpPacket.resetChecksum();
		byte[] udpSerialized = udpPacket.serialize();
		udpPacket.deserialize(udpSerialized, 0, udpSerialized.length);
		short udpCalcCksum = udpPacket.getChecksum();
		if (orignUdpCksum != udpCalcCksum) { return; }
		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl()) { return; }
		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();
		if (udpPacket.getSourcePort() != UDP.RIP_PORT || udpPacket.getDestinationPort() != UDP.RIP_PORT){
			return;
		}
		RIPv2 rip = (RIPv2)udpPacket.getPayload();
		if (rip.getCommand() == RIPv2.COMMAND_REQUEST){
			if (etherPacket.getDestinationMAC().toBytes()==BROADCAST &&
					ipPacket.getDestinationAddress()==IPv4.toIPv4Address(UDP_IP)){
				this.sendRipPacket(etherPacket, inIface, true, false);
			}
			else {
				this.sendRipPacket(etherPacket, inIface, false, false);
			}

		}
		else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE){
			for (RIPv2Entry entry : rip.getEntries()){
				int address = entry.getAddress();
				int subnetMask = entry.getSubnetMask();
				int cost = entry.getMetric() + 1;
				int nextHop = entry.getNextHopAddress();
				long timeStamp = System.currentTimeMillis();
				RIPv2Entry newEntry = new RIPv2Entry(address, subnetMask, cost, timeStamp);
				newEntry.setNextHopAddress(nextHop);
				this.ripTable.update(newEntry);
			}
		}
	}

	public void initializeRip(){
		t.schedule(new TimerTask() {
			@Override
			public void run() {
				sendTimedResponse();
			}
		}, 0, 10000);
	}

	private void sendTimedResponse(){
		for (Iface iface : this.interfaces.values()) {
			this.sendRipPacket(null, iface, true, false);
		}
	}

	/** This function sends ICMP packets */
    private void send_ICMP_error(Ethernet etherPacket, Iface inIface, byte type, byte code, boolean echo){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstIP = ipPacket.getSourceAddress();
		RouteEntry bestMatch = this.routeTable.lookup(dstIP);
		if (bestMatch==null){
			return;
		}
		Iface outIface = bestMatch.getInterface();
		int nextHop = bestMatch.getGatewayAddress();
		if (0==nextHop){
			nextHop = dstIP;
		}
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry==null){
			return;
		}
		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(echo ? ipPacket.getDestinationAddress() : outIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());
		icmp.setIcmpType(type);
		icmp.setIcmpCode(code);
		int ipLength = (int)(ipPacket.getTotalLength());
		byte original[] = ipPacket.serialize();
		int notEchoLen = ipPacket.getHeaderLength() * 4 + 8;
		byte icmpPayload[] = new byte[4 + (echo ? ipLength : notEchoLen)];
		System.arraycopy(original, 0, icmpPayload, 4, (echo ? ipLength : notEchoLen));
		data.setData(icmpPayload);
		// Now all done, send packet
		String error;
		if (type == 11 && code == 0){
			error = "time exceeded";
		}
		else if (type == 3 && code == 0){
			error = "destination net unreachable";
		}
		else if (type == 3 && code == 1){
			error = "destination host unreachable";
		}
		else if (type == 3 && code == 3){
			error = "destination port unreachable";
		}
		else { error = "echo"; }
		System.out.println("All done, send " + error + " ICMP packet");
		this.sendPacket(ether, outIface);
	}

	/** This function handles ARP packets */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface){
		ARP arpPacket = (ARP) etherPacket.getPayload();
		if (arpPacket.getOpCode() == ARP.OP_REPLY){
			int ipAddr = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			MACAddress MacAddr = new MACAddress(arpPacket.getSenderHardwareAddress());
			arpCache.insert(MacAddr, ipAddr);
			for (PacketInterfacePair pair : arpQueue.get(ipAddr)){
				Ethernet packet = pair.packet;
				Iface outIface = pair.outIface;
				packet.setDestinationMACAddress(MacAddr.toBytes());
				this.sendPacket(packet, outIface);
			}
			arpQueue.remove(ipAddr);

		}
		else if (arpPacket.getOpCode() == ARP.OP_REQUEST){
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			if (targetIp != inIface.getIpAddress()){
				return;
			}
			Ethernet ether = new Ethernet();
			ether.setEtherType(Ethernet.TYPE_ARP);
			ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
			ARP arp = new ARP();
			arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
			arp.setProtocolType(ARP.PROTO_TYPE_IP);
			arp.setHardwareAddressLength(((byte)Ethernet.DATALAYER_ADDRESS_LENGTH));
			arp.setProtocolAddressLength((byte)4);
			arp.setOpCode(ARP.OP_REPLY);
			arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
			arp.setSenderProtocolAddress(inIface.getIpAddress());
			arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
			arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
			ether.setPayload(arp);
			this.sendPacket(ether, inIface);
		}
	}
}

/** Just a tuple */
class PacketInterfacePair
{
	Ethernet packet;
	Iface inIface;
	Iface outIface;
	PacketInterfacePair(Ethernet packet, Iface inIface, Iface outIface){
		this.packet = packet;
		this.inIface = inIface;
		this.outIface = outIface;
	}
}