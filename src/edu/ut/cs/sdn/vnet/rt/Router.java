package edu.ut.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.Timer;
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
import net.floodlightcontroller.packet.UDP;
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

    private final long UNSOLICITED_WAIT = 10_000L;
    private final long CHECK_ROUTE_ENTRY_WAIT = 30_000L;

    private final int RIP_MULTICAST_IP = IPv4.toIPv4Address("224.0.0.9");

    /** ARP cache for the router */
    private final ArpCache arpCache;

    private Map<Integer, Queue<BasePacket>> waitingQ;
    private Lock arpLock;

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
        this.arpLock = new ReentrantLock();
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

    public void broadcastRIP(byte command) {
        for (Iface iface : this.interfaces.values()) {
            Ethernet ether = new Ethernet();
            ether.setEtherType(Ethernet.TYPE_IPv4);
            ether.setSourceMACAddress(iface.getMacAddress().toBytes());
            ether.setDestinationMACAddress(BROADCAST);

            IPv4 ip = new IPv4();
            ip.setTtl((byte) 64);
            ip.setProtocol(IPv4.PROTOCOL_UDP);
            ip.setSourceAddress(iface.getIpAddress());
            ip.setDestinationAddress(RIP_MULTICAST_IP);

            UDP udp = new UDP();
            udp.setSourcePort(UDP.RIP_PORT);
            udp.setDestinationPort(UDP.RIP_PORT);

            RIPv2 rip = new RIPv2();
            rip.setEntries(ripv2.getEntries());
            rip.setCommand(command);
            
            ether.setPayload(ip);
            ip.setPayload(udp);
            udp.setPayload(rip);
            
            sendPacket(ether, iface);
        }
    }

    public void runRIP()
    {
        for (Iface iface : this.interfaces.values()) {
            this.routeTable.insert(iface.getIpAddress(),    // dstIp
                                   0,                       // gwIp
                                   iface.getSubnetMask(),   // maskIp
                                   iface);                  // iface
            
            RIPv2Entry newEntry = new RIPv2Entry(iface.getIpAddress(), iface.getSubnetMask(), 0);
            this.ripv2.addEntry(newEntry);
        }
        
        // Send out RIP Request on each of these interfaces (RIPv2 is a BasePacket)
        broadcastRIP(RIPv2.COMMAND_REQUEST);

        // Send out unsolicited responses every 10 seconds
        Thread thread = new Thread() {
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(UNSOLICITED_WAIT);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    broadcastRIP(RIPv2.COMMAND_RESPONSE);
                }
            }
        };
        thread.start();
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
                // this.generateARP(etherPacket, inIface, ARP.OP_REPLY, 0);
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
     * Handle a RIP packet received on a specific interface.
     * @param ripPacket the RIP packet that was received
     * @param inIface the interface on which the packet was received
     */
    private void handleRipPacket(Ethernet etherPacket, Iface inIface)
    {
        System.out.println("------ " + this.getHost() + " ------\n" + this.routeTable.toString());

        IPv4 ip = (IPv4) etherPacket.getPayload();
        UDP udp = (UDP) ip.getPayload();
        RIPv2 rip = (RIPv2) udp.getPayload();

        boolean response = (rip.getCommand() == RIPv2.COMMAND_RESPONSE);
        boolean request = (rip.getCommand() == RIPv2.COMMAND_REQUEST);

        // Handle RIP request -> should just send back our RIP 
        if (request) {
            Ethernet resp_ether = new Ethernet();
            resp_ether.setEtherType(Ethernet.TYPE_IPv4);
            resp_ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
            resp_ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

            IPv4 resp_ip = new IPv4();
            resp_ip.setTtl((byte) 64);
            resp_ip.setProtocol(IPv4.PROTOCOL_UDP);
            resp_ip.setSourceAddress(inIface.getIpAddress());
            resp_ip.setDestinationAddress(ip.getSourceAddress());

            UDP resp_udp = new UDP();
            resp_udp.setSourcePort(UDP.RIP_PORT);
            resp_udp.setDestinationPort(UDP.RIP_PORT);

            RIPv2 resp_rip = new RIPv2();
            resp_rip.setEntries(ripv2.getEntries());
            resp_rip.setCommand(RIPv2.COMMAND_RESPONSE);
            
            resp_ether.setPayload(resp_ip);
            resp_ip.setPayload(resp_udp);
            resp_udp.setPayload(resp_rip);
            
            sendPacket(resp_ether, inIface);
        }

        // Received a RIP response, so we'll update our RIP with new info
        List<RIPv2Entry> incomingRIPEntries = rip.getEntries();
        for (int i = 0; i < incomingRIPEntries.size(); i++) {
            RIPv2Entry incomingRIPEntry = incomingRIPEntries.get(i);
            
            // This is their current information for the distance from address to nextHop
            int theirMetricAddressToNextHop = incomingRIPEntry.getMetric();
            int address = incomingRIPEntry.getAddress();
            int nextHopAddress = incomingRIPEntry.getNextHopAddress();

            // Need to compare with my information for the same addresses
            RIPv2Entry myNextHopEntry = null;
            RIPv2Entry myAddressEntry = null;
            List<RIPv2Entry> myEntries = this.ripv2.getEntries();
            for (int j = 0; j < myEntries.size(); j++) {
                if (myEntries.get(j).getAddress() == nextHopAddress)
                    myNextHopEntry = myEntries.get(j);
                if (myEntries.get(j).getAddress() == address)

                    myAddressEntry = myEntries.get(j);
            }

            int myMetricToAddress = myAddressEntry == null ? Integer.MAX_VALUE : myAddressEntry.getMetric();
            int myMetricToNextHop = myNextHopEntry == null ? Integer.MAX_VALUE : myNextHopEntry.getMetric();
            int dist = myMetricToAddress + theirMetricAddressToNextHop + 1;
            if (dist <= myMetricToNextHop) {
                if (myNextHopEntry != null)
                    myNextHopEntry.setMetric(dist);
                else
                    ripv2.addEntry(new RIPv2Entry(nextHopAddress, inIface.getSubnetMask(), dist));
                    
                if (this.routeTable.lookup(nextHopAddress) != null)
                    this.routeTable.update(nextHopAddress, inIface.getIpAddress(), address, inIface);
                else 
                    this.routeTable.insert(nextHopAddress, inIface.getIpAddress(), address, inIface);
            }
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

        // handle RIP packet separately
        if (this.isRipPacket(etherPacket)) {
            this.handleRipPacket(etherPacket, inIface);
            return;
        }

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
            // arpLock.lock();
            // try {
            //     if (waitingQ.get(nextHop) == null) {
            //         waitingQ.put(nextHop, new LinkedList<BasePacket>(Arrays.asList(etherPacket)));
            //         Thread arpRequest = new ARPRequest(etherPacket, inIface, outIface, nextHop);
            //         arpRequest.start();
            //     } else {
            //         waitingQ.get(nextHop).add(etherPacket);
            //     }
            // } finally {
            //     arpLock.unlock();
            // }
            synchronized(this.waitingQ) {
                if (waitingQ.get(nextHop) == null) {
                    waitingQ.put(nextHop, new LinkedList<BasePacket>(Arrays.asList(etherPacket)));
                    // Thread arpRequest = new ARPRequest(etherPacket, inIface, outIface, nextHop);
                    // arpRequest.start();
                } else {
                    waitingQ.get(nextHop).add(etherPacket);
                }
            }
            return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    private boolean isRipPacket(Ethernet etherPacket)
    {
        assert etherPacket.getEtherType() == Ethernet.TYPE_IPv4;
    
        IPv4 ipPacket = (IPv4) etherPacket.getPayload();

        if (ipPacket.getDestinationAddress() != RIP_MULTICAST_IP)
            return false;
        if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
            return false;
        
        UDP packet = (UDP) ipPacket.getPayload();
        if (packet.getDestinationPort() != UDP.RIP_PORT)
            return false;
            
        return true;
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
                    // arpLock.lock();
                    // try {
                    //     assert waitingQ.get(this.targetIPAddress) != null;
                    //     for (BasePacket packet : waitingQ.get(this.targetIPAddress)) {
                    //         Ethernet ether = (Ethernet) packet;
                    //         ether.setDestinationMACAddress(destMac.toBytes());
                    //         sendPacket(ether, outIface);
                    //     }
                    //     waitingQ.remove(targetIPAddress);
                    // } finally {
                    //     arpLock.unlock();
                    // }
                    synchronized(waitingQ) {
                        assert waitingQ.get(this.targetIPAddress) != null;
                        for (BasePacket packet : waitingQ.get(this.targetIPAddress)) {
                            Ethernet ether = (Ethernet) packet;
                            ether.setDestinationMACAddress(destMac.toBytes());
                            sendPacket(ether, outIface);
                        }
                        waitingQ.remove(targetIPAddress);
                    }
                    return;
                }
            }
            
            // all attempts have failed, drop all packets and generate ICMP for each
            // arpLock.lock();
            // try {
            synchronized(waitingQ) {
                assert waitingQ.get(this.targetIPAddress) != null;
                for (BasePacket packet : waitingQ.get(this.targetIPAddress)) {
                    Ethernet ether = (Ethernet) packet;
                    generateICMP(ether, inIface, (byte) 3, (byte) 1);
                }
                waitingQ.remove(targetIPAddress);
            }
            // } finally {
            //     arpLock.unlock();
            // }
        }
    }
}
