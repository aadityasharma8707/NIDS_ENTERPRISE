import os
import json
import psycopg2
import time
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP

# Load environment variables
load_dotenv()

def packet_callback(db_conn):
    def callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            src_port = 0
            dst_port = 0
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Direct-to-Cloud Injection
            if db_conn:
                try:
                    cur = db_conn.cursor()
                    cur.execute("""
                        INSERT INTO alerts (source_ip, dest_ip, attack_type, confidence, inference_time_ms) 
                        VALUES (%s, %s, %s, %s, %s)
                    """, (src_ip, dst_ip, 'LIVE_TRAFFIC', 1.0, 0.0))
                    db_conn.commit()
                    cur.close()
                    print(f"    [+] TELEMETRY TRANSMITTED -> CLOUD SIEM: {src_ip} -> {dst_ip}")
                except Exception as e:
                    print(f"    [!] UPLINK_ERROR: Cloud sync failed ({e})")
                    
    return callback

def main():
    db_url = os.getenv('RENDER_EXTERNAL_DB_URL')
    
    print(f"--- NIDS-X FORWARD DEPLOYED SENSOR (DIRECT-UPLINK MODE) ---")
    
    if not db_url:
        print("[!] ERROR: RENDER_EXTERNAL_DB_URL not found in .env. Deployment aborted.")
        return

    print("[*] Initializing Cloud SIEM handshake...")
    db_conn = None
    try:
        db_conn = psycopg2.connect(db_url)
        print("[+] CLOUD_SYNC_ESTABLISHED: Remote Database ONLINE.")
    except Exception as e:
        print(f"[!] CRITICAL_CONNECTION_FAILURE: {e}")
        return

    print(f"[*] Sniffer Active. Monitoring default interface...")
    
    try:
        # Sniff packets and invoke callback for each
        sniff(prn=packet_callback(db_conn), store=0)
    except KeyboardInterrupt:
        print("\n[!] Sensor deactivated by operator.")
    except Exception as e:
        print(f"\n[!] CRITICAL_SENSOR_ERROR: {e}")
    finally:
        if db_conn:
            db_conn.close()
            print("[*] Cloud connection closed.")

if __name__ == "__main__":
    main()
