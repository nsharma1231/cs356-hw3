package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
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
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{ 
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
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
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
        if (0 == ipPacket.getTtl())
        { 
			Ethernet ether = new Ethernet();
			ether.setEtherType(Ethernet.TYPE_IPv4);
			// set to the MAC address of the out interface obtained by performing a lookup in the route table
			// invariably this will be the interface on which the original packet arrived

			IPv4 ip_packet = (IPv4)etherPacket.getPayload();
			int dstAddr = ip_packet.getSourceAddress();
	
			// Find matching route table entry 
			RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
	
			// If no entry matched, do nothing
			if (null == bestMatch) {
				System.out.println("best match is null"); 
				return; 
			}
	
			// Make sure we don't sent a packet back out the interface it came in
			Iface outIface = bestMatch.getInterface();
			if (outIface == inIface) { 
				System.out.println("outIface = inIface sending packet to itself");
				return; 
			}
	
			// Set source MAC address in Ethernet header
			ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
	
			// If no gateway, then nextHop is IP destination
			int nextHop = bestMatch.getGatewayAddress();
			if (0 == nextHop)
			{ nextHop = dstAddr; }
	
			// Set destination MAC address in Ethernet header
			ArpEntry arpEntry = this.arpCache.lookup(nextHop);
			if (null == arpEntry) {
				System.out.println("arp entry is null");
				return;
			}
			etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

			IPv4 ip = new IPv4();
			ip.setTtl((byte)64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(inIface.getIpAddress());
			ip.setDestinationAddress(ip_packet.getSourceAddress());

			ICMP icmp = new ICMP();
			icmp.setIcmpCode((byte)0);
			icmp.setIcmpType((byte)11);
			// Create a byte array and initialize with 0's.
			// (1) 4 bytes of padding
			// (2) the original IP header from the packet that triggered the error message
			// (3) the 8 bytes following the IP header in the original packet.
			// Then, leave 1st 4 bytes of the array and fill in the other required data as specified in the assignment description.
			Data data = new Data();
			byte[] payloadData = new byte[ip_packet.getHeaderLength() + 12]; // ip.length + 12
			byte[] _payloadData = ip_packet.serialize();
			for (int i = 4; i < payloadData.length && (i - 4) < _payloadData.length; i++) {
				payloadData[i] = _payloadData[i - 4];
			}
			
			data.setData(payloadData);

			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);

			// send it on the interface that is obtained from the longest prefix match 
			// in the route table for the source IP of original packet 
			// (invariably this will be the interface on which the original packet arrived). 
			// You should drop the original packet after sending the time exceeded message.
			this.sendPacket(ether, inIface);
			return;
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ return; }
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
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
        { return; }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { return; }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}
