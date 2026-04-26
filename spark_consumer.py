import json
import joblib
import warnings
import psycopg2
import time
import os
import requests
from dotenv import load_dotenv
from confluent_kafka import Consumer, KafkaException, KafkaError
from preprocess_utils import preprocess_flow

load_dotenv()
WEBHOOK_URL = os.getenv('WEBHOOK_URL', None)

# Suppress XGBoost warnings if necessary
warnings.filterwarnings('ignore')

REVERSE_LABEL_MAP = {
    0: 'BENIGN',
    1: 'Bot',
    2: 'BruteForce',
    3: 'DoS',
    4: 'PortScan',
    5: 'WebAttack'
}

def send_webhook_alert(source_ip, attack_type, confidence):
    if not WEBHOOK_URL:
        return
    
    payload = {
        "content": f"🚨 **CRITICAL THREAT DETECTED** 🚨\n**Type:** {attack_type}\n**Source IP:** {source_ip}\n**Confidence:** {confidence:.4f}"
    }
    
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except Exception as e:
        print(f"Failed to send webhook: {e}")

def main():
    print("Loading XGBoost model...")
    try:
        model = joblib.load('xgboost_multiclass_realistic.pkl')
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Failed to load model: {e}")
        return

    # Initialize PostgreSQL connection
    db_conn = None
    max_retries = 10
    print("Connecting to PostgreSQL...")
    for i in range(max_retries):
        try:
            db_conn = psycopg2.connect(
                host=os.getenv("DB_HOST", "localhost"),
                database=os.getenv("DB_NAME", "nids_db"),
                user=os.getenv("DB_USER", "admin"),
                password=os.getenv("DB_PASS", "nids_password"),
                port="5432"
            )
            db_conn.autocommit = True
            print("Connected to PostgreSQL successfully.")
            break
        except Exception as e:
            print(f"Waiting for PostgreSQL... ({i+1}/{max_retries})")
            time.sleep(3)
    
    if not db_conn:
        print("Warning: Failed to connect to PostgreSQL. Alerts will not be saved.")

    # Kafka consumer configuration
    conf = {
        'bootstrap.servers': os.getenv("KAFKA_BROKER", "localhost:9092"),
        'group.id': 'nids_consumer_group',
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(conf)
    topic = 'live-network-flows'
    
    # Wait for Kafka
    print("Connecting to Kafka...")
    for i in range(max_retries):
        try:
            # Fetch metadata to check connection
            meta = consumer.list_topics(timeout=3.0)
            if meta:
                print("Connected to Kafka successfully.")
                break
        except Exception as e:
            print(f"Waiting for Kafka... ({i+1}/{max_retries})")
            time.sleep(3)
    
    try:
        consumer.subscribe([topic])
        print(f"Subscribed to topic '{topic}'. Polling for messages...")

        while True:
            msg = consumer.poll(timeout=1.0)
            
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    raise KafkaException(msg.error())
            
            value_str = msg.value().decode('utf-8')
            try:
                flow_data = json.loads(value_str)
                source_ip = flow_data.get('Source IP', 'Unknown')
                dest_ip = flow_data.get('Destination IP', 'Unknown')
                
                # Preprocess flow
                df = preprocess_flow(flow_data)
                
                # Predict
                start_time = time.time()
                prediction = model.predict(df)[0]
                end_time = time.time()
                
                inference_time_ms = (end_time - start_time) * 1000
                
                # If the model has predict_proba, we can get confidence, otherwise default to 1.0
                confidence = 1.0
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(df)[0]
                    confidence = float(max(proba))
                
                if prediction != 0:
                    attack_type = REVERSE_LABEL_MAP.get(prediction, f"Unknown_Attack_{prediction}")
                    print(f"🚨 [ALARM] Threat Detected: {attack_type} | Source: {source_ip} (Confidence: {confidence:.2f}, Inference: {inference_time_ms:.2f}ms)")
                    
                    if attack_type != 'BENIGN' and confidence >= 0.95:
                        send_webhook_alert(source_ip, attack_type, confidence)
                else:
                    attack_type = 'BENIGN'
                    print(f"Analyzing Flow: {source_ip} -> {dest_ip} [BENIGN] (Inference: {inference_time_ms:.2f}ms)")
                    
                if db_conn:
                    try:
                        cur = db_conn.cursor()
                        cur.execute(
                            "INSERT INTO alerts (source_ip, dest_ip, attack_type, confidence, inference_time_ms) VALUES (%s, %s, %s, %s, %s)",
                            (source_ip, dest_ip, attack_type, confidence, inference_time_ms)
                        )
                        cur.close()
                    except Exception as e:
                        print(f"Failed to insert record into database: {e}")
                
            except json.JSONDecodeError:
                print(f"Failed to decode message: {value_str}")
                
    except KeyboardInterrupt:
        print("Consumer interrupted by user.")
    finally:
        consumer.close()
        if db_conn:
            db_conn.close()
        print("Consumer closed.")

if __name__ == '__main__':
    main()
