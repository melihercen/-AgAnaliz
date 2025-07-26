# AgAnaliz
#Ağ Trafik Analiz Aracı

Bu Python tabanlı araç, `.pcap` veya `.pcapng` formatındaki ağ trafiği kayıtlarını (Wireshark dump) analiz eder. Özellikle aşağıdaki güvenlik anormalliklerini ve trafiği incelemek amacıyla tasarlanmıştır:

---

## 🚀 Özellikler

- 📍 **MAC Adresi ve IP Adresi Tespiti**
- 🔁 **IP - MAC Eşlemesi**
- 🛑 **Port Tarama Tespiti**  
  Bir kaynaktan 10'dan fazla farklı port erişimi tespit edildiğinde saldırgan olarak işaretlenir.
- 🧅 **ARP Zehirlenmesi (Spoofing) Tespiti**  
  Aynı IP’ye ait farklı MAC adresleri algılandığında uyarı verir.
- 🌐 **Aşırı Trafik Üreten IP Tespiti**  
  1000’den fazla paket gönderen IP'ler listelenir.
