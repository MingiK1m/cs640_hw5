package edu.wisc.cs.sdn.simpledns;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdata;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataName;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataString;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class LocalDNSServer {
	private boolean DEBUG = true; 
	
	private class EC2AddressRegion{
		String region;
		int subnetMask;
		int ipv4Addr;
		
		public EC2AddressRegion(int ipv4, int mask, String region){
			this.ipv4Addr = ipv4;
			this.subnetMask = mask;
			this.region = region;
		}
	}
	public static final int DNS_PORT_NUM = 53;
	public static final int SIMPLE_DNS_PORT_NUM = 8053;

	public static final int BUF_SIZE = 1024;
	public static final int SOCKET_TIMEOUT_MS = 2000;

	private InetAddress rootNSAddr;
	private ArrayList<EC2AddressRegion> ec2array;

	public LocalDNSServer(String rootNameServer, String ec2FilePath) throws UnknownHostException{
		this.rootNSAddr = InetAddress.getByName(rootNameServer);
		this.ec2array = new ArrayList<EC2AddressRegion>();
		
		// read ec2 file
		BufferedReader in;
		
		try
		{
			in = new BufferedReader(new FileReader(ec2FilePath));
			while (in.ready()) { 
				String line = in.readLine(); // 72.44.32.0/19,Virginia
				String[] ipmask_region = line.split(",");
				String[] ip_mask = ipmask_region[0].split("/");
				
				String region = ipmask_region[1];
				int ip = ByteBuffer.wrap(InetAddress.getByName(ip_mask[0]).getAddress()).getInt();
				short mask = Short.parseShort(ip_mask[1]);
				
				int subnetMask = 0;
				subnetMask = 0xffffffff ^ (1 << 32 - mask) - 1;
				
				ec2array.add(new EC2AddressRegion(ip, subnetMask, region));
			}
			in.close();
			
		}
		catch(Exception e)
		{
			System.out.println("Could not read instances: "+e);
		}
	}

	public void runDNSServer() throws IOException{
		InetAddress clientAddress;
		int clientPort;
		
		DatagramSocket dnsServSock;

		dnsServSock = new DatagramSocket(SIMPLE_DNS_PORT_NUM);
		
		byte[] rcvBuf = new byte[BUF_SIZE];
		DatagramPacket rcvPkt = new DatagramPacket(rcvBuf, rcvBuf.length);

		while(true){
			dnsServSock.receive(rcvPkt);

			clientPort = rcvPkt.getPort();
			clientAddress = rcvPkt.getAddress();

			DNS reqDnsPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());
			if(reqDnsPkt.isQuery()){
				if(reqDnsPkt.getOpcode() == DNS.OPCODE_STANDARD_QUERY){
					List <DNSQuestion> queries = reqDnsPkt.getQuestions();
					for(DNSQuestion query : queries){
						DNS ansDnsPkt = resolveQuery(dnsServSock, query, reqDnsPkt.isRecursionDesired());
						ansDnsPkt.setId(reqDnsPkt.getId());
						ansDnsPkt.setQuestions(reqDnsPkt.getQuestions());

						byte[] respPktSerialized = ansDnsPkt.serialize();

						DatagramPacket respPkt = new DatagramPacket(respPktSerialized, respPktSerialized.length);
						respPkt.setPort(clientPort);
						respPkt.setAddress(clientAddress);
						
						dnsServSock.send(respPkt);
					}
				}
			}
		}
	}
	
	private DNS resolveQuery(DatagramSocket dnsServSock, DNSQuestion query, boolean isRecurs) throws IOException {
		DNS ansDnsPkt = null;

		byte[] rcvBuf = new byte[BUF_SIZE];
		DatagramPacket rcvPkt = new DatagramPacket(rcvBuf, rcvBuf.length);
		
		switch(query.getType()){
		case DNS.TYPE_A: // IPv4
		case DNS.TYPE_AAAA: // IPv6
		case DNS.TYPE_CNAME: // another DN for a particular host
		case DNS.TYPE_NS: // DNS server that has the DN
		{
			DNS dnsOutPkt = new DNS();
			DNSQuestion question = new DNSQuestion(query.getName(), query.getType());
			dnsOutPkt.setOpcode(DNS.OPCODE_STANDARD_QUERY);
			dnsOutPkt.addQuestion(question);
			dnsOutPkt.setId((short)0x00aa);
			dnsOutPkt.setRecursionDesired(isRecurs);
			dnsOutPkt.setRecursionAvailable(false);
			dnsOutPkt.setQuery(true);

			byte[] dnsOutPktSerialized = dnsOutPkt.serialize();

			DatagramPacket queryPkt = new DatagramPacket(dnsOutPktSerialized, dnsOutPktSerialized.length);
			queryPkt.setAddress(rootNSAddr);
			queryPkt.setPort(DNS_PORT_NUM);

			dnsServSock.send(queryPkt);

			dnsServSock.receive(rcvPkt);

			ansDnsPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());
			System.out.println(ansDnsPkt);

			if(!isRecurs){
				return ansDnsPkt;
			}
			
			List <DNSResourceRecord> answers = new ArrayList<DNSResourceRecord>();
			List <DNSResourceRecord> authorities = new ArrayList<DNSResourceRecord>();
			List <DNSResourceRecord> additionals = new ArrayList<DNSResourceRecord>();
			
			while(ansDnsPkt.getRcode()==DNS.RCODE_NO_ERROR){
				if(ansDnsPkt.getAnswers().isEmpty()){
					// answer not found
					authorities = ansDnsPkt.getAuthorities();
					additionals = ansDnsPkt.getAdditional();
					if(ansDnsPkt.getAuthorities().isEmpty()) break;
					for(DNSResourceRecord authRecord : ansDnsPkt.getAuthorities()){
						if(authRecord.getType() == DNS.TYPE_NS){
							DNSRdataName authStr = (DNSRdataName)authRecord.getData();
							if(ansDnsPkt.getAdditional().isEmpty()){
								queryPkt.setAddress(InetAddress.getByName(authStr.getName()));

								dnsServSock.send(queryPkt);

								dnsServSock.receive(rcvPkt);

								ansDnsPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());
								System.out.println(ansDnsPkt);
							} else {
								for(DNSResourceRecord addRecord : ansDnsPkt.getAdditional()){
									if(authStr.getName().contentEquals(addRecord.getName())){
										if(addRecord.getType() == DNS.TYPE_A){
											DNSRdataAddress addrData = (DNSRdataAddress)addRecord.getData();
											queryPkt.setAddress(addrData.getAddress());

											dnsServSock.send(queryPkt);

											dnsServSock.receive(rcvPkt);

											ansDnsPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());
											System.out.println(ansDnsPkt);
										}
									}
								}
							}
						}
					}
				} else {
					// an answer found
					for(DNSResourceRecord ansRecord : ansDnsPkt.getAnswers()){
						answers.add(ansRecord);
						if(ansRecord.getType() == DNS.TYPE_CNAME){
							boolean isInAnswers = false;
							for(DNSResourceRecord record : ansDnsPkt.getAnswers()){
								// check the resolved CNAME is included in answers
								String name = record.getName();
								String data = ((DNSRdataName)ansRecord.getData()).getName();
								
								if(name.equals(data)) isInAnswers = true;
							}
							if(isInAnswers) continue;
							
							if(query.getType() == DNS.TYPE_A || query.getType() == DNS.TYPE_AAAA){
								/* RESOLVE CNAME HERE*/
								DNSQuestion cnameQuery = new DNSQuestion(((DNSRdataName)ansRecord.getData()).getName(), query.getType());
								DNS resolvedDnsPkt = resolveQuery(dnsServSock, cnameQuery, isRecurs);
								
								for(DNSResourceRecord resolvedRecord :resolvedDnsPkt.getAnswers()){
									answers.add(resolvedRecord);
								}

								authorities = resolvedDnsPkt.getAuthorities();
								additionals = resolvedDnsPkt.getAdditional();
								/* RESOLVE CNAME HERE */
							}
						}
					}
					break;
				}
			}

			// SEND RESPONSE
			ansDnsPkt.setAuthorities(authorities);
			ansDnsPkt.setAdditional(additionals);

			ArrayList<DNSResourceRecord> EC2Records = new ArrayList<DNSResourceRecord>();
            for (DNSResourceRecord record : answers) {
                if (record.getType() == DNS.TYPE_A) {
                    DNSRdataAddress address = (DNSRdataAddress) (record.getData());
                    String EC2region = this.match(address.getAddress());
                    if (EC2region != null) {
                        DNSRdata text = new DNSRdataString(EC2region+"-"+address.getAddress().getHostAddress());
                        DNSResourceRecord ECrecord = new DNSResourceRecord(record.getName(), (short) 16, text);
                        EC2Records.add(ECrecord);
                    }
                }
            }
            
            for(DNSResourceRecord record : EC2Records){
            	answers.add(record);
            }

			ansDnsPkt.setAnswers(answers);

		}
			break;
		default :
			// IGNORE ALL THE OTHERS
			break;
		}
		
		return ansDnsPkt; 
	}
	
	private String match(InetAddress addr){
		String rtn = null;
		
		for(EC2AddressRegion ec2 : ec2array){
			int maskedAddr = ByteBuffer.wrap(addr.getAddress()).getInt() & ec2.subnetMask;
			int ec2RegionAddr = ec2.ipv4Addr & ec2.subnetMask;
			
			if(maskedAddr == ec2RegionAddr) return ec2.region;
		}
		
		return rtn;
	}
}
