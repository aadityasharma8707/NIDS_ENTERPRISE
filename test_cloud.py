import os
import psycopg2
from dotenv import load_dotenv

# Load credentials from .env
load_dotenv()
url = os.getenv('RENDER_EXTERNAL_DB_URL')

print(f"--- NIDS-X CLOUD UPLINK TEST ---")
print(f"[*] Target: {url[:30]}...")

try:
    # Attempt to connect and inject a test alert
    conn = psycopg2.connect(url)
    cur = conn.cursor()
    
    # We use a dummy test alert to verify the pipeline
    cur.execute("""
        INSERT INTO alerts (source_ip, dest_ip, attack_type, confidence, inference_time_ms) 
        VALUES (%s, %s, %s, %s, %s)
    """, ('1.1.1.1', '2.2.2.2', 'CLOUD_TEST_UPLINK', 0.99, 0.0))
    
    conn.commit()
    print("\n🚀 SUCCESS! Data is now in the Render Cloud!")
    print("[+] Check your Render URL - the 'CLOUD_TEST_UPLINK' alert should be visible.")
    
    cur.close()
    conn.close()
except Exception as e:
    print(f"\n❌ FAILED: {e}")
    print("[!] Ensure your RENDER_EXTERNAL_DB_URL in .env is correct and has no quotes/spaces.")
