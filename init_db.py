import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def init_db():
    print("Connecting to PostgreSQL to initialize database...")
    db_url = os.getenv("RENDER_EXTERNAL_DB_URL")
    try:
        if db_url:
            print("Connecting to Render Cloud Database...")
            conn = psycopg2.connect(db_url)
        else:
            print("Connecting to Local PostgreSQL...")
            conn = psycopg2.connect(
                host=os.getenv("DB_HOST", "localhost"),
                database=os.getenv("DB_NAME", "nids_db"),
                user=os.getenv("DB_USER", "admin"),
                password=os.getenv("DB_PASS", "nids_password"),
                port="5432"
            )
        cur = conn.cursor()
        
        print("Creating table 'alerts' if it doesn't exist...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                attack_type TEXT,
                confidence FLOAT,
                inference_time_ms FLOAT
            )
        """)
        
        print("Ensuring existing table has 'inference_time_ms' column...")
        try:
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS inference_time_ms FLOAT")
        except Exception as e:
            pass # Ignore if not supported or exists
        
        conn.commit()
        cur.close()
        conn.close()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Failed to initialize database: {e}")

if __name__ == "__main__":
    init_db()
