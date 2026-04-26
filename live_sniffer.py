import os
import json
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP
from confluent_kafka import Producer

# Load environment variables
load_dotenv()

def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")

def packet_callback(producer, topic):
    def callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            src_port = 0
            dst_port = 0
            payload_len = 0
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload_len = len(packet[TCP].payload)
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload_len = len(packet[UDP].payload)
            
            # Format basic features as JSON
            flow_data = {
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Source Port': src_port,
                'Destination Port': dst_port,
                'Protocol': proto,
                'Payload Length': payload_len,
                'Flow Duration': 0 # mock duration for packet-level capture
            }
            
            print(f"Captured: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [Proto: {proto}]")
            
            # Stream to Kafka
            producer.produce(topic, json.dumps(flow_data).encode('utf-8'), callback=delivery_report)
            producer.poll(0)
    return callback

def main():
    kafka_broker = os.getenv('KAFKA_BROKER', 'localhost:9092')
    producer = Producer({'bootstrap.servers': kafka_broker})
    topic = 'live-network-flows'
    
    print(f"Starting live sniffer... capturing from default interface.")
    print(f"Streaming packets to Kafka topic: {topic} at {kafka_broker}")
    try:
        # Sniff packets and invoke callback for each
        sniff(prn=packet_callback(producer, topic), store=0)
    except KeyboardInterrupt:
        print("Stopping sniffer...")
    finally:
        producer.flush()

if __name__ == "__main__":
    main()
