import psycopg2
import pandas as pd
from fpdf import FPDF
from datetime import datetime

def generate_report():
    print("Connecting to database...")
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="nids_db",
            user="admin",
            password="nids_password",
            port="5432"
        )
        query = "SELECT * FROM alerts"
        df = pd.read_sql(query, conn)
        conn.close()
    except Exception as e:
        print(f"Failed to connect to database or fetch data: {e}")
        return

    if df.empty:
        print("No data available to generate report.")
        return

    print("Generating report statistics...")
    
    # 1. Summarize the number of 'BENIGN' vs 'Attack' flows
    total_flows = len(df)
    benign_count = len(df[df['attack_type'] == 'BENIGN'])
    attack_count = total_flows - benign_count

    # 2. Identify the 'Top 3 Attacking IPs'
    attacks_df = df[df['attack_type'] != 'BENIGN']
    top_attacking_ips = []
    if not attacks_df.empty:
        top_ips = attacks_df['source_ip'].value_counts().head(3)
        top_attacking_ips = [(ip, count) for ip, count in top_ips.items()]

    avg_inference = df['inference_time_ms'].mean() if 'inference_time_ms' in df.columns else 0.0

    print("Creating PDF...")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    
    # Header
    pdf.cell(200, 10, "NIDS Automated Summary Report", ln=True, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(200, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)
    
    # Summary
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "1. Overall Traffic Summary", ln=True)
    pdf.set_font("Arial", '', 12)
    pdf.cell(200, 10, f"Total Flows Analyzed: {total_flows}", ln=True)
    pdf.cell(200, 10, f"Benign Flows: {benign_count}", ln=True)
    pdf.cell(200, 10, f"Attack Flows Detected: {attack_count}", ln=True)
    pdf.cell(200, 10, f"Average Inference Time: {avg_inference:.2f} ms", ln=True)
    pdf.ln(10)

    # Top Attacking IPs
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "2. Top 3 Attacking IPs", ln=True)
    pdf.set_font("Arial", '', 12)
    
    if top_attacking_ips:
        for idx, (ip, count) in enumerate(top_attacking_ips, 1):
            pdf.cell(200, 10, f"  {idx}. {ip} ({count} attacks)", ln=True)
    else:
        pdf.cell(200, 10, "  No attacks detected.", ln=True)
    
    pdf.ln(10)
    
    # Attack Breakdown
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "3. Attack Type Breakdown", ln=True)
    pdf.set_font("Arial", '', 12)
    
    if not attacks_df.empty:
        attack_counts = attacks_df['attack_type'].value_counts()
        for attack_type, count in attack_counts.items():
            pdf.cell(200, 10, f"  - {attack_type}: {count}", ln=True)
    else:
        pdf.cell(200, 10, "  No attacks to categorize.", ln=True)

    report_filename = "NIDS_Summary_Report.pdf"
    pdf.output(report_filename)
    print(f"Report successfully saved to {report_filename}")

if __name__ == "__main__":
    generate_report()
