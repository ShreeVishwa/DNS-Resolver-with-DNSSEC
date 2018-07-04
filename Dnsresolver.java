import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import org.xbill.DNS.DNSSEC.DNSSECException;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.*;
import java.util.*;

public class Dnsresolver {

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		Scanner sc = new Scanner(System.in);
		String server = sc.next();
		server += ".";
		String type = sc.next();
          // System.out.println(type);
		int q_type = Type.A;
		if(type == "A") q_type = Type.A;
		if("NS".equals(type)) q_type = Type.NS;
		if("MX".equals(type)) {
               q_type = Type.MX;
               // System.out.println("Yes Mx");
          }
		ArrayList<String> root_servers = new ArrayList<>();
		ArrayList<String> additional_servers = new ArrayList<>();
		File file = new File("hosts.txt");
		Scanner input = new Scanner(file);
		while(input.hasNext()) {
		    String nextLine = input.nextLine();
		    String[] splited = nextLine.split("\\s+");
		    root_servers.add(splited[1]);
		}
		// System.out.println("Before Input");
		input.close();
		// System.out.println("After Input");
		boolean soa_flag = false;
		int j = 0, k = 0;
          Dnsresolver dns = new Dnsresolver();
		long s_time = 0, e_time = 0;

		// System.out.println(j);
          Name q_name = Name.fromString(server);
		String question = "";
		Record ans = null;
          // System.out.println(full);
		while(j < root_servers.size()) {
			// System.out.println("Hello");
			s_time = System.currentTimeMillis();

			//Query the root servers iteratively

			String dom_name = root_servers.get(j);
			j++;
			Resolver res = new SimpleResolver(dom_name);
			Record rec = Record.newRecord(q_name, q_type, DClass.IN);
			Message query = Message.newQuery(rec);
			Message response = res.send(query);
			// System.out.println(response);
               Resolver dnssec_res = new ExtendedResolver();
               dnssec_res.setEDNS(0,0,ExtendedFlags.DO,null);
               dnssec_res.setIgnoreTruncation(false);
               dnssec_res.setTimeout(20);
               Record dnssec_rec = Record.newRecord(q_name, Type.ANY, DClass.IN);
               Message dnssec_query = Message.newQuery(dnssec_rec);
			Message dnssec_response = dnssec_res.send(dnssec_query);

			//DNSSEC verification

               int dnssec = dns.Verifydnssec(dnssec_response);
			// System.out.println(s_time);
               if(dnssec == 1) System.out.println("DNSSEC is configured and everything is verified");
               else if(dnssec == 0) System.out.println("DNSSEC is not supported");
               else System.out.println("DNSSEC is supported but the digital signature could not be verified");
			System.out.println("\n");
               while(true){

				//If the response answer section length is 0 then query the servers recursively from the additional and authority sections

                    if(response.getSectionArray(Section.ANSWER).length == 0){

					//If we get the response as an SOA type then leave it as it is and break
					if(response.getSectionArray(Section.AUTHORITY)[0].getType() == Type.SOA){
						soa_flag = true;
						break;
					}
					Record[] responseRecords = response.getSectionArray(Section.ADDITIONAL);
					if(responseRecords.length == 0) {
						responseRecords = response.getSectionArray(Section.AUTHORITY);
					}
					additional_servers.clear();
					for(int i=0;i<responseRecords.length;i++){
						additional_servers.add(responseRecords[i].rdataToString());
					}
					k = 0;

					while(k < additional_servers.size()){
						res = new SimpleResolver(additional_servers.get(k++));
						response = res.send(query);
						if(response != null) break;
					}

                    }
                    // else
                    else break;
               }

			if(soa_flag){
				Record[] responseRecords = response.getSectionArray(Section.AUTHORITY);
				e_time = System.currentTimeMillis();
				System.out.println("QUESTION SECTION :");
				if(question == "") System.out.println(response.getQuestion().toString());
				else System.out.println(question);
				System.out.println("\n");
				System.out.println("ANSWER SECTION :");
				if(ans != null) System.out.println(ans);
				for(int i=0;i<responseRecords.length;i++) System.out.println(responseRecords[i]);
				System.out.println("\n");
				System.out.println("Query Time : " + (e_time - s_time)/10 + "msec");
				System.out.println("When : " + new Date());
				System.out.println("MSG SIZE rcvd " + response.numBytes());
				// System.out.println(responseRecords[0]);
                    // System.out.println(responseRecords[responseRecords.length - 1].rdataToString());
                    break;
			}

			else{
	               Record[] responseRecords = response.getSectionArray(Section.ANSWER);
	               if(responseRecords[0].getType() == Type.A || responseRecords[0].getType() == Type.AAAA || responseRecords[0].getType() == Type.NS || responseRecords[0].getType() == Type.MX){
					e_time = System.currentTimeMillis();
					System.out.println("QUESTION SECTION :");
					if(question == "") System.out.println(response.getQuestion().toString());
					else System.out.println(question);
					System.out.println("\n");
					System.out.println("ANSWER SECTION :");
					if(ans != null) System.out.println(ans);
					for(int i=0;i<responseRecords.length;i++) System.out.println(responseRecords[i]);
					System.out.println("\n");
					System.out.println("Query Time : " + (e_time - s_time)/10 + "msec");
					System.out.println("When : " + new Date());
					System.out.println("MSG SIZE rcvd " + response.numBytes());
					// System.out.println(responseRecords[0]);
	                    // System.out.println(responseRecords[responseRecords.length - 1].rdataToString());
	                    break;
	                    // continue;
	               }
	               else{
	                    q_name = Name.fromString(responseRecords[0].rdataToString());
					ans = responseRecords[0];
					question = response.getQuestion().toString();
	                    // break;
	               }
			}
               // break;
		}
		if(j==root_servers.size()) System.out.println("Couldn't resolve the address");
     }

     public int Verifydnssec(Message response) throws IOException, UnknownHostException{
          RRset[] rrset = response.getSectionRRsets(Section.ANSWER);
          boolean ksk_verify = false;
          boolean zsk_verify = false;
          boolean ds_break = false;
          for(int i=0;i<rrset.length;i++){
               Iterator<Record> signatures = rrset[i].sigs();
               if(!signatures.hasNext()) return 0;
               while(signatures.hasNext()){
                    RRSIGRecord sigrec = (RRSIGRecord)signatures.next();
                    Name origin = sigrec.getSigner();
                    int key_match = sigrec.getFootprint();
                    DNSKEYRecord key_to_verify = null;
                    Resolver dnskey_res = new ExtendedResolver();
                    dnskey_res.setEDNS(0,0,ExtendedFlags.DO,null);
                    dnskey_res.setIgnoreTruncation(false);
                    dnskey_res.setTimeout(20);
                    Record dnskey_rec = Record.newRecord(origin, Type.DNSKEY, DClass.IN);
                    Message dnskey_query = Message.newQuery(dnskey_rec);
     			Message dnskey_response = dnskey_res.send(dnskey_query);
                    RRset[] dnskey_set = dnskey_response.getSectionRRsets(Section.ANSWER);
                    for(int j=0;j<dnskey_set.length;j++){
                         Iterator<Record> dns_rrs = dnskey_set[j].rrs();
                         while(dns_rrs.hasNext()){
                              Record dns_rrs_rec = dns_rrs.next();
                              if(dns_rrs_rec instanceof DNSKEYRecord){
                                   DNSKEYRecord key_rec = (DNSKEYRecord)dns_rrs_rec;
                                   if(key_match == key_rec.getFootprint()){
                                        key_to_verify = key_rec;
                                        break;
                                   }
                              }
                         }
                         Iterator<Record> dns_key_sigs = dnskey_set[j].sigs();
                         if(!dns_key_sigs.hasNext()) return -1;
                         while(dns_key_sigs.hasNext()){
                              RRSIGRecord dns_key_sig_rec = (RRSIGRecord)dns_key_sigs.next();
                              if(dns_key_sig_rec.getFootprint() == key_match){
                                   try{
                                        DNSSEC.verify(dnskey_set[j],dns_key_sig_rec,key_to_verify);
                                        ksk_verify = true;
                                   } catch(DNSSECException e){
                                        System.out.println("Error in verifying with the Key-Signing Keys");
                                   }
                              }
                         }
                    }
                    try{
                         DNSSEC.verify(rrset[i],sigrec,key_to_verify);
                         zsk_verify = true;
                    } catch(DNSSECException e){
                         System.out.println("Error in Verifying with the Zone-Signing Key");
                    }
                    // Name ds_signer = sigrec.getSigner();
                    // if(ds_signer.toString.length() == 1){
                    //      ds_break = true;
                    // }
                    // if(!ds_break){
                    //      Resolver dns_ds = new ExtendedResolver();
                    //      dns_ds.setEDNS(0,0,ExtendedFlags.DO,null);
                    //      dns_ds.setIgnoreTruncation(false);
                    //      dns_ds.setTimeout(20);
                    //      Record dns_ds_rec = Record.newRecord(ds_signer, Type.DS, DClass.IN);
                    //      Message dns_ds_query = Message.newQuery(dns_ds_rec);
          		// 	Message dns_ds_response = dnskey_res.send(dns_ds_query);
                    //      RRset[] dns_ds_set = dns_ds_response.getSectionRRsets(Section.ANSWER);
                    //      for(int l = 0; l < dns_ds_set.length; l++){
                    //           Iterator<Record> dns_ds_sigs = dns_ds_set[i].sigs();
                    //           if(dns_ds_sigs.next() instanceof RRSIGRecord){
                    //                origin = (RRSIGRecord)dns_ds_sigs.next();
                    //                continue Ds_verify_loop;
                    //           }
                    //      }
                    // }
               }
          }
          if(ksk_verify && zsk_verify) return 1;
          else if(!ksk_verify && zsk_verify) return 2;
          else if(ksk_verify && !zsk_verify) return 3;
          else return 4;
     }
}
