# traceroute
program Otomasi Jaringan
#!/usr/bin/env python3

import sys
import time
from scapy.all import IP, UDP, ICMP, sr1, conf

# --- Konfigurasi ---
MAX_HOPS = 30       # Batas maksimum lompatan (router)
TIMEOUT = 2         # Waktu tunggu balasan (detik)
BASE_PORT = 33434   # Port UDP default untuk traceroute
# --------------------

def detect_problem(hop, rtt, last_rtt, timeout_streak):
    """
    Fungsi ini menganalisis data untuk 'mendeteksi kendala'.
    """
    problem = "" # Tidak ada masalah
    
    # 1. Deteksi Packet Loss / Timeout
    if rtt is None:
        if timeout_streak > 1:
            problem = f"🔥 KENDALA: Packet loss terdeteksi (Timeout {timeout_streak}x berturut-turut)"
        else:
            problem = "(Router ini mungkin memblokir ICMP)"
        return problem

    # 2. Deteksi Latency (Ping) Tinggi
    # Kita anggap latensi 'tinggi' jika di atas 200ms
    if rtt > 200:
        problem = f"⚠️ KENDALA: Latensi tinggi! ({rtt:.0f} ms)"
    
    # 3. Deteksi Lonjakan Latency (Latency Jump)
    # Jika latensi saat ini > 3x lipat dari latensi hop sebelumnya (dan > 50ms)
    elif (last_rtt > 0) and (rtt > (last_rtt * 3)) and (rtt > 50):
        problem = f"⚠️ KENDALA: Lonjakan latensi! (dari {last_rtt:.0f} ms ke {rtt:.0f} ms)"

    return problem

def run_traceroute(target):
    """
    Menjalankan logika traceroute utama.
    """
    
    # Matikan output verbose default dari Scapy
    conf.verb = 0
    
    print(f"Memulai traceroute ke '{target}' (max {MAX_HOPS} hops)...\n")
    
    last_rtt = 0         # Untuk menyimpan RTT dari hop sebelumnya
    timeout_streak = 0   # Menghitung timeout berturut-turut
    
    for ttl in range(1, MAX_HOPS + 1):
        
        # 1. Buat Paket (Craft Packet)
        # Kita mengirim paket UDP ke port yang (semoga) tidak digunakan
        # TTL akan meningkat di setiap loop
        pkt = IP(dst=target, ttl=ttl) / UDP(dport=BASE_PORT + ttl)
        
        start_time = time.time()
        
        # 2. Kirim Paket dan Tunggu 1 Balasan (sr1)
        reply = sr1(pkt, timeout=TIMEOUT)
        
        end_time = time.time()
        
        # Hitung Round Trip Time (RTT) dalam milidetik
        rtt = (end_time - start_time) * 1000
        
        hop_info = ""
        current_rtt = None # Set None jika timeout
        
        # 3. Analisis Balasan
        if reply is None:
            # --- TIDAK ADA BALASAN (TIMEOUT) ---
            hop_info = "*\t*\t*"
            timeout_streak += 1
            
        elif reply.type == 11 and reply.code == 0:
            # --- BALASAN 'TIME EXCEEDED' (INI ADALAH ROUTER DI JALUR) ---
            hop_info = f"{reply.src}\t\t{rtt:.2f} ms"
            timeout_streak = 0 # Reset hitungan timeout
            current_rtt = rtt
            
        elif reply.type == 3 and reply.code == 3:
            # --- BALASAN 'PORT UNREACHABLE' (INI ADALAH TUJUAN AKHIR) ---
            hop_info = f"{reply.src}\t\t{rtt:.2f} ms"
            timeout_streak = 0
            current_rtt = rtt
            print(f" {ttl}\t{hop_info}")
            print("\n✅ Selesai! Tujuan telah tercapai.")
            break # Hentikan loop
            
        else:
            # Balasan tidak terduga
            hop_info = f"Balasan aneh: tipe={reply.type} kode={reply.code}"
            timeout_streak = 0

        # 4. Deteksi Kendala
        problem_msg = detect_problem(ttl, current_rtt, last_rtt, timeout_streak)
        
        # Cetak hasil
        print(f" {ttl}\t{hop_info}\t{problem_msg}")

        # Simpan RTT saat ini untuk perbandingan di hop berikutnya
        if current_rtt is not None:
            last_rtt = current_rtt

    else:
        # Jika loop selesai tanpa 'break'
        print("\n❌ Gagal! Tujuan tidak tercapai setelah {MAX_HOPS} hops.")


# --- Program Utama Dimulai ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Penggunaan: sudo python3 {sys.argv[0]} <hostname_atau_ip>")
        print("Contoh: sudo python3 py_traceroute.py www.cisco.com")
        sys.exit(1)
        
    target = sys.argv[1]
    run_traceroute(target)
