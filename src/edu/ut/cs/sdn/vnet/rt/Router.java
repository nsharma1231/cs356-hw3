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

	private void generateICMP(Ethernet etherPacket, Iface inIface, byte type, byte code) {
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(etherPacket.getDestinationMACAddress());
		// TODO: do we need to look up in the arp cache?
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		ICMP icmp = new ICMP();			
		icmp.setIcmpType(type);
		icmp.setIcmpCode(code);
		
		Data data = new Data();
		byte[] payloadData = new byte[ipPacket.getHeaderLength() * 4 + 12];
		byte[] _payloadData = ipPacket.serialize();
		for (int i = 4; i < payloadData.length && (i - 4) < _payloadData.length; i++) {
			payloadData[i] = _payloadData[i - 4];
		}
		
		data.setData(payloadData);

		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		
		this.forwardIpPacket(ether, inIface, true);
	}

	private void generateEcho(Ethernet etherPacket, Iface inIface) {
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		// TODO: do we need to look up in the arp cache?
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		ICMP icmp = new ICMP();			
		icmp.setIcmpType((byte) 3);
		icmp.setIcmpCode((byte) 3);
		
		Data data = new Data();
		byte[] payloadData = new byte[ipPacket.getHeaderLength() * 4 + 12];
		byte[] _payloadData = ipPacket.serialize();
		for (int i = 4; i < payloadData.length && (i - 4) < _payloadData.length; i++) {
			payloadData[i] = _payloadData[i - 4];
		}
		
		data.setData(payloadData);

		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		
		this.forwardIpPacket(ether, inIface, true);
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
			this.generateICMP(etherPacket, inIface, (byte) 11, (byte) 0);
			return;
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress()) { 
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP || ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
					this.generateICMP(etherPacket, inIface, (byte) 3, (byte) 3);
				}
				else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP payload = (ICMP) ipPacket.getPayload();
					if (payload.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
						this.generateEcho(etherPacket, inIface);
					}
				}
				return; 
			}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface, false);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface, boolean icmp)
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
        if (null == bestMatch) {
			this.generateICMP(etherPacket, inIface, (byte) 3, (byte) 0);
			System.out.println("no entry matched");
			return;
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (!icmp && outIface == inIface) {
			System.out.println("outIface == inIface"); 
			return; 
		}

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        {
			System.out.println("0 == nextHop");
			nextHop = dstAddr;
		}

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry) {
			System.out.println("arpEntry null");
			this.generateICMP(etherPacket, inIface, (byte) 3, (byte) 1);
			return; 
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}
