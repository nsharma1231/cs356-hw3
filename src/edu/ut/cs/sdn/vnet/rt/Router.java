package edu.ut.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.TimerTask;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
    public static final byte XFF = (byte) 0xFF;
    public static final byte[] BROADCAST = new byte[]{XFF, XFF, XFF, XFF, XFF, XFF};
    public static final byte ZRO = (byte) 0x00;
    public static final byte[] ZERO = new byte[]{ZRO, ZRO, ZRO, ZRO, ZRO, ZRO};

    /** Routing table for the router */
    private final RouteTable routeTable;
    private final RIPv2 ripv2;

    /** ARP cache for the router */
    private final ArpCache arpCache;

    private Map<Integer, Queue<BasePacket>> waitingQ;
    private Lock lock;

    public static final boolean VERBOSE = true;
    private void LOG(String message)
    {
        if (VERBOSE)
            System.err.println(message);
    }

    /**
     * Creates a router for a specific host.
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile)
    {
        super(host,logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
        this.waitingQ = new HashMap<>();
        this.lock = new ReentrantLock();
        this.ripv2 = new RIPv2();
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

    public void runRIP()
    {
        for (Iface iface : this.interfaces.values()) {
            /*
             *  (1) Add entries to the route table for the subnets that are directly reachable via the router's interfaces 
             *  (2) Based on the IP address and netmask associated with each of the router's interfaces. 
             *  (3) These entries should have no gateway.
             */
            this.routeTable.insert(iface.getIpAddress(),    // dstIp
                                   0,                       // gwIp
                                   iface.getSubnetMask(),   // maskIp
                                   iface);                  // iface
            
            this.ripv2.addEntry(new RIPv2Entry(iface.getIpAddress(), iface.getSubnetMask(), 0));
        }

        TimerTask task = new TimerTask() {
            public void run() {
                RIPv2 ripPacket = new RIPv2();
                
                sendPacket(null, null)
            }
        };
    }

    // WHAT IS PASSED IN???
    public void distanceVec() {
        /*
         * (1) Distance d1 on its own route table entry corresponding to the nextHopAddress
         * (2) Distance d2 as the metric value on the RIP entry, that says address is d2 hops away from nextHopAddress
         * (3) Distance d3 on its own route table entry corresponding to address (current path to address)
         * (4) It will updates its own route table for address if d1 + d2 <= d3, and sets new time and new distance , and gateway as the nextHopAddress
         */
        
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
        case Ethernet.TYPE_ARP:
            this.handleArpPacket(etherPacket, inIface);
            break;
        default:
            break;
        // Ignore all other packet types, for now
        }

        /********************************************************************/
    }

    /**
     * Handle an ARP packet received on a specific interface.
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */
    private void handleArpPacket(Ethernet etherPacket, Iface inIface)
    {
        assert etherPacket.getEtherType() == Ethernet.TYPE_ARP;

        LOG("[INFO] Handle ARP packet");

        ARP arpPacket = (ARP) etherPacket.getPayload();

        switch (arpPacket.getOpCode()) {
            case ARP.OP_REQUEST:
                this.generateARP(etherPacket, inIface, ARP.OP_REPLY, 0);
                break;
            case ARP.OP_REPLY:
                MACAddress macAddress = new MACAddress(arpPacket.getSenderHardwareAddress());
                int ip = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
                this.arpCache.insert(macAddress, ip);
                // gets sent out in thread
                break;
            default:
                break;

        }
    }

    /**
     * Handle an IPv4 packet received on a specific interface.
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */ 
    private void handleIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
        assert etherPacket.getEtherType() == Ethernet.TYPE_IPv4;

        LOG("[INFO] Handle IP packet");

        // Get IP header
        IPv4 ipPacket = (IPv4)etherPacket.getPayload();

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum) return;

        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (ipPacket.getTtl() == 0)
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
                        this.generateICMP(etherPacket, inIface, (byte) 0, (byte) 0);
                    }
                }
                return;
            }
        }

        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface, false);
    }
    
    private void generateICMP(Ethernet etherPacket, Iface inIface, byte type, byte code)
    {
        IPv4 ipPacket = (IPv4)etherPacket.getPayload();

        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setSourceMACAddress(etherPacket.getDestinationMACAddress());
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
		if (code == 0 && type == 0) {
			byte[] payloadData = ipPacket.getPayload().getPayload().serialize();
			data.setData(payloadData);
		} else {
			byte[] payloadData = new byte[ipPacket.getHeaderLength() * 4 + 12];
			byte[] _payloadData = ipPacket.serialize();
			for (int i = 4; i < payloadData.length && (i - 4) < _payloadData.length; i++) {
				payloadData[i] = _payloadData[i - 4];
			}
			data.setData(payloadData);
		}

        ether.setPayload(ip);
        ip.setPayload(icmp);
        icmp.setPayload(data);
        this.forwardIpPacket(ether, inIface, true);
    }

    private void generateARP(Ethernet etherPacket, Iface inIface, short opCode, int targetIPAddress)
    {
        ARP arpPacket = null;
        
        if (opCode == ARP.OP_REPLY) {
            arpPacket = (ARP) etherPacket.getPayload();
            int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
            int ourIp = inIface.getIpAddress();
            if (targetIp != ourIp) {
                return;
            }
        }

        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_ARP);
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ether.setDestinationMACAddress(opCode == ARP.OP_REPLY ? etherPacket.getSourceMACAddress() : Router.BROADCAST);

        ARP arpHeader = new ARP();
        arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
        arpHeader.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arpHeader.setProtocolAddressLength((byte) 4);
        arpHeader.setOpCode(opCode);
        arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
        arpHeader.setSenderProtocolAddress(inIface.getIpAddress());
        arpHeader.setTargetHardwareAddress(opCode == ARP.OP_REPLY ? arpPacket.getSenderHardwareAddress() : Router.ZERO);
        arpHeader.setTargetProtocolAddress(opCode == ARP.OP_REPLY ? arpPacket.getSenderProtocolAddress() :
                                                                    IPv4.toIPv4AddressBytes(targetIPAddress));

        ether.setPayload(arpHeader);
        
        if (opCode == ARP.OP_REQUEST) {
            for (Iface iface : this.interfaces.values()) {
                this.sendPacket(ether, iface);
            }
        }
        else {
            this.sendPacket(ether, inIface);
        }
    }

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface, boolean icmp)
    {
        // Make sure it's an IP packet
        assert etherPacket.getEtherType() == Ethernet.TYPE_IPv4;
        LOG("[INFO] Forward IP packet");

        // Get IP header
        IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (bestMatch == null) {
            this.generateICMP(etherPacket, inIface, (byte) 3, (byte) 0);
            return;
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (!icmp && outIface == inIface) {
            return;
        }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (nextHop == 0)
        {
            nextHop = dstAddr;
        }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (arpEntry == null) {
            lock.lock();
            try {
                if (waitingQ.get(nextHop) == null) {
                    waitingQ.put(nextHop, new LinkedList<BasePacket>(Arrays.asList(etherPacket)));
                    Thread arpRequest = new ARPRequest(etherPacket, inIface, outIface, nextHop);
                    arpRequest.start();
                } else {
                    waitingQ.get(nextHop).add(etherPacket);
                }
            } finally {
                lock.unlock();
            }
            return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    class ARPRequest extends Thread
    {
        public static final long RETRY_TIME = 1 * 1000L;
        public static final int NUM_RETRIES = 3;
        
        private Ethernet etherPacket;
        private Iface inIface;
        private Iface outIface;
        private int targetIPAddress;

        public ARPRequest(Ethernet etherPacket, Iface inIface, Iface outIface, int targetIPAddress)
        {
            this.etherPacket = etherPacket;
            this.inIface = inIface;
            this.outIface = outIface;
            this.targetIPAddress = targetIPAddress;
        }

        private void sendRequest()
        {
            generateARP(etherPacket, inIface, ARP.OP_REQUEST, this.targetIPAddress);
        }

        private boolean cacheUpdated()
        {
            ArpEntry arpEntry = arpCache.lookup(this.targetIPAddress);
            return arpEntry != null;
        }

        private boolean attempt()
        {
            sendRequest();

            // wait for one second
            try {
                Thread.sleep(RETRY_TIME);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            // check if a reply has been received
            return cacheUpdated();
        }

        public void run()
        {
            for (int i = 0; i < NUM_RETRIES; ++i) {

                // check if we got a reply
                if (attempt()) {
                    MACAddress destMac = arpCache.lookup(targetIPAddress).getMac();
                    // send all packets
                    lock.lock();
                    try {
                        assert waitingQ.get(this.targetIPAddress) != null;
                        for (BasePacket packet : waitingQ.get(this.targetIPAddress)) {
                            Ethernet ether = (Ethernet) packet;
                            ether.setDestinationMACAddress(destMac.toBytes());
                            sendPacket(ether, outIface);
                        }
                        waitingQ.remove(targetIPAddress);
                    } finally {
                        lock.unlock();
                    }

                    return;
                }
            }
            
            // all attempts have failed, drop all packets and generate ICMP for each
            lock.lock();
            try {
                assert waitingQ.get(this.targetIPAddress) != null;
                for (BasePacket packet : waitingQ.get(this.targetIPAddress)) {
                    Ethernet ether = (Ethernet) packet;
                    generateICMP(ether, inIface, (byte) 3, (byte) 1);
                }
                waitingQ.remove(targetIPAddress);
            } finally {
                lock.unlock();
            }
        }
    }
}
