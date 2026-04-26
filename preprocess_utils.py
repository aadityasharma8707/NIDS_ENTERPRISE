import pandas as pd
import numpy as np

MODEL_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

def map_label(label):
    if label == "BENIGN":
        return "BENIGN"
    elif label in ["DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris"]:
        return "DoS"
    elif label == "PortScan":
        return "PortScan"
    elif "Web Attack" in label:
        return "WebAttack"
    elif label in ["FTP-Patator", "SSH-Patator"]:
        return "BruteForce"
    elif label == "Bot":
        return "Bot"
    else:
        return "DROP"

def align_features(raw_dict):
    """
    Produces a DataFrame with the exact 77 columns and order discovered for the model.
    Fills matching columns from the Kafka message and sets all other columns to 0.0.
    """
    aligned_data = {feat: 0.0 for feat in MODEL_FEATURES}
    
    for key, value in raw_dict.items():
        if key in aligned_data:
            try:
                aligned_data[key] = float(value)
            except (ValueError, TypeError):
                pass
                
    return pd.DataFrame([aligned_data], columns=MODEL_FEATURES)

def preprocess_flow(raw_dict):
    """
    Converts a raw JSON dictionary into a Pandas DataFrame for downstream analysis.
    """
    # Align features to the 77 model features
    df = align_features(raw_dict)
    
    # Feature Scaling Placeholder
    # Scaling must occur AFTER the train-test split logic
    # TODO: Implement scaling logic later
    
    return df
