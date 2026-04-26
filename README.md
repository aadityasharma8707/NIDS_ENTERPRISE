# Enterprise Level Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system capable of processing network flows, running an XGBoost classification model to identify threats, and visualizing results on a live Streamlit dashboard.

## Architecture

The system is built on a scalable data pipeline:

1. **Kafka (Data Ingestion)**: Network traffic (simulated from CSV or live) is pushed into a Kafka topic (`live-network-flows`) by a Python producer (`kafka_producer.py`).
2. **XGBoost (Threat Classification)**: A Python consumer (`spark_consumer.py`) acts as the analysis engine, pulling messages from Kafka and passing them to an XGBoost multi-class machine learning model.
3. **PostgreSQL (Persistence)**: The analysis results, confidence levels, and inference times are logged into a PostgreSQL database (`nids_db`). 
4. **Streamlit (SOC Dashboard)**: A live SOC (Security Operations Center) dashboard (`dashboard.py`) constantly queries the database to present real-time traffic health, recent threats, and analytics.

## Getting Started

### 1. Requirements

Ensure Docker and Python are installed, then install the required Python packages:
```bash
pip install -r requirements.txt
```

### 2. Setup the Database

If running for the first time, initialize the PostgreSQL schema:
```bash
python init_db.py
```

### 3. Run the Application

A master controller script is provided to automate the setup. It will check your Docker containers, start the analysis engine in the background, and open the SOC Dashboard:
```bash
python run_app.py
```

*Note: You may need to manually start the Kafka Producer to simulate traffic if it is not already running:*
```bash
python kafka_producer.py
```

## Reporting

You can generate an automated PDF summary report of all analyzed traffic, benign/attack flow counts, and top attacking IPs.

### Generate the PDF Report:
Run the following script:
```bash
python generate_report.py
```
This will create a `NIDS_Summary_Report.pdf` file in your workspace.

## Scalability Note

This architecture is designed for high throughput. To handle larger volumes of network traffic:
- **More Kafka Partitions**: By increasing the number of partitions for the `live-network-flows` Kafka topic, the data stream can be split across multiple brokers.
- **Multiple Consumers**: You can run multiple instances of `spark_consumer.py` sharing the same `group.id` (`nids_consumer_group`). Kafka will automatically distribute the partitions among the consumer instances, scaling the machine learning inference horizontally without duplicating work.
