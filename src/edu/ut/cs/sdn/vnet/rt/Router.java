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
			// EtherType - set to Ethernet.TYPE_IPv4
			ether.setEtherType(Ethernet.TYPE_IPv4);
			// Source MAC - set to the MAC address of the out interface obtained by performing a
			// lookup in the route table (invariably this will be the interface on which the original packet arrived)
			// ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
			ether.setSourceMACAddress(etherPacket.getDestinationMACAddress());
			// Destination MAC - set to the MAC address of the next hop, determined by performing a
			// lookup in the route table followed by a lookup in the ARP cache
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

			IPv4 ip_packet = (IPv4)etherPacket.getPayload();
			/* int dstAddr = ip_packet.getSourceAddress(); 
	
			// Find matching route table entry 
			RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
	
			// If no entry matched, do nothing
			if (null == bestMatch) {
				System.out.println("best match is null"); 
				return; 
			}
			
			int nextHop = bestMatch.getGatewayAddress();
			if (0 == nextHop)
			{ nextHop = dstAddr; }
	
			// Set destination MAC address in Ethernet header
			ArpEntry arpEntry = this.arpCache.lookup(nextHop);
			if (null == arpEntry) {
				System.out.println("arp entry is null");
				return;
			} */
			// ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

			IPv4 ip = new IPv4();
			ip.setTtl((byte)64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			// Source IP - set to the IP address of the interface on which the original packet arrived
			ip.setSourceAddress(inIface.getIpAddress());
			//  set to the source IP of the original packet the ICMP header you must populate the following fields:
			ip.setDestinationAddress(ip_packet.getSourceAddress());

			ICMP icmp = new ICMP();
			icmp.setIcmpCode((byte)0);
			icmp.setIcmpType((byte)11);
			
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
			
			this.sendPacket(ether, inIface);
			System.out.println("icmp src: " + IPv4.fromIPv4Address(ip_packet.getSourceAddress()));
			System.out.println("icmp dest: " +  IPv4.fromIPv4Address(ip_packet.getDestinationAddress()));
			System.out.println("sent icmp packet");
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
