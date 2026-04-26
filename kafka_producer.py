import csv
import json
import time
import argparse
from confluent_kafka import Producer

def json_serializer(data):
    return json.dumps(data).encode('utf-8')

def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        print(f"Message delivery failed: {err}")
    else:
        pass # Optional: print(f"Message delivered to {msg.topic()} [{msg.partition()}]")

def main():
    parser = argparse.ArgumentParser(description="Network Flow Kafka Data Simulator")
    parser.add_argument('--csv-file', default='data/network_traffic.csv', help="Path to the network flows CSV file")
    parser.add_argument('--topic', default='live-network-flows', help="Kafka topic to publish to")
    parser.add_argument('--broker', default='localhost:9092', help="Kafka broker address")
    parser.add_argument('--delay', type=float, default=0.1, help="Delay between messages in seconds")
    
    args = parser.parse_args()

    print(f"Connecting to Kafka broker at {args.broker}...")
    # Initialize Kafka Producer
    conf = {'bootstrap.servers': args.broker}
    producer = Producer(conf)
    print("Connected.")

    print(f"Reading from {args.csv_file} and publishing to topic '{args.topic}' with {args.delay}s delay...")
    
    try:
        with open(args.csv_file, mode='r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            
            for row in csv_reader:
                # Trigger any available delivery report callbacks from previous produce() calls
                producer.poll(0)

                # Convert the row dictionary to a JSON payload
                payload = json_serializer(row)
                
                # Asynchronously produce a message. The delivery report callback
                # will be triggered from poll() above, or flush() below, when the message has
                # been successfully delivered or failed permanently.
                producer.produce(
                    args.topic, 
                    value=payload, 
                    callback=delivery_report
                )
                
                print(f"Queued: {row}")
                
                # Sleep for the configured delay
                time.sleep(args.delay)
                
    except FileNotFoundError:
        print(f"Error: The file {args.csv_file} was not found. Please ensure it exists.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Wait for any outstanding messages to be delivered and delivery report
        # callbacks to be triggered.
        print("Flushing outstanding messages...")
        producer.flush()
        print("Producer closed.")

if __name__ == "__main__":
    main()
