from scapy.all import rdpcap,Ether,IP,TCP,ARP
from collections import Counter
def analyze_pcap(pcapng_file):
    mac_addresses=set()
    ip_addresses=set()
    port_control={}

    arp_cache={}
    arp_anomalies=set()
    ip_counter=Counter()
    ip_mac_map={}

    packets=rdpcap(pcapng_file)

    for packet in packets:
        if packet.haslayer(Ether):
            mac_addresses.add(packet[Ether].src)
            mac_addresses.add(packet[Ether].dst)

        if packet.haslayer(IP):
            ip_src=packet[IP].src
            ip_dst=packet[IP].dst
            ip_addresses.add(ip_src)
            ip_addresses.add(ip_dst)
            ip_counter[ip_src]+=1

            if packet.haslayer(Ether):
                ip_mac_map[ip_src]=packet[Ether].src
                ip_mac_map[ip_dst]=packet[Ether].dst

        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip=packet[IP].src
            dst=packet[IP].dst
            ip_addresses.add(packet[IP].src)
            ip_addresses.add(packet[IP].dst)
            port=packet[TCP].dport
                
            if ip not in port_control:
                port_control[ip]={'targets':{},'total_ports':0}

            if dst not in port_control[ip]['targets']:
                port_control[ip]['targets'][dst]=set()
            port_control[ip]['targets'][dst].add(port)
            port_control[ip]['total_ports']+=1

               
        
        if packet.haslayer(ARP):
            if packet[ARP].op==2:
                sender_ip=packet[ARP].psrc
                sender_mac=packet[ARP].hwsrc

                if sender_ip in arp_cache and arp_cache[sender_ip]!=sender_mac:
                    anomaly_detail=f"ARP Zehirlenmesı Potansıyleı: IP {sender_ip} daha önce MAC {arp_cache[sender_ip]} ile ilişkilendirilirken, şimdi MAC {sender_mac} ile görüldü. (Paket Numarası: {packets.index(packet) + 1})"
                    arp_anomalies.add(anomaly_detail)
                else:
                    arp_cache[sender_ip]=sender_mac

    print("\n Tespit Edilen MAC Adresleri")
    for mac in sorted(list(mac_addresses)):
        print(f"- {mac}")

    print("\nTespit Edilen IP Adresleri:")
    for ip in sorted(list(ip_addresses)):
        print(f"-{ip}")

    print("\nIPve MAC eşleşmesi:")
    for ip,mac in ip_mac_map.items():
        print(f"{ip} -> {mac}")

    print("\nPort tarama tespiti:")
    if port_control:
        for attacker, info in port_control.items():
            for target,portlar in info['targets'].items():
                if len(portlar)>10:
                    print(f"Saldırgan IP: {attacker}")
                    print(f"Hedef IP: {target}")
                    print(f"Yapılan Port Tarama: {sorted(portlar)}\n")
    else:
        print("Hiçbir sonuç bulunmadı.")

   
    print("ARP Zehirlenmesi Tespiti:")
    if arp_anomalies:
        for anomaly in arp_anomalies:
            print(f"- {anomaly}")
    else:
        print("Hiçbir sonuç bulunmadı.")

    print("Aşırı Trafik yapan IP'ler:")
    found=False
    if ip_counter:
        for ip,count in ip_counter.items():
            if count>1000:
                print(f"-{ip}: {count} paket gonderdi ")
                found=True
    if not found:
        print("Hiçbir sonuç bulunmadı.")


dosya=input("Pcapng dosyası:").strip()
analyze_pcap(dosya)           
