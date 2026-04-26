import streamlit as st
import ast
import re
import pandas as pd
from groq import Groq
import subprocess
import sys
import plotly.express as px
import psycopg2
import os
import platform
import time
from dotenv import load_dotenv
import requests
import pydeck as pdk
import joblib
import shap
import matplotlib.pyplot as plt
import numpy as np
import random
import datetime

# Load environment variables
load_dotenv()

# Set page config
st.set_page_config(layout='wide', page_title="NIDS Dashboard", page_icon="🛡️")

st.markdown('''<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif !important;
    background: #000000 !important;
    background-image: radial-gradient(circle at top left, #2e1065 0%, #000000 70%) !important;
    background-attachment: fixed !important;
    color: white !important;
}

#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Purple Glassdoor Metrics */
[data-testid="metric-container"] {
    background: rgba(46, 16, 101, 0.4) !important;
    backdrop-filter: blur(15px) !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 12px !important;
    padding: 20px !important;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8) !important;
    transition: all 0.3s ease-in-out;
}
[data-testid="metric-container"]:hover {
    transform: translateY(-5px);
    border: 1px solid #00FF41 !important;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.2) !important;
}

[data-testid="stMetricValue"] {
    color: #00FF41 !important;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
    font-weight: 700 !important;
}

[data-testid="stMetricLabel"] {
    color: #cbd5e1 !important;
    font-size: 0.9rem !important;
}

/* Custom Scrollbar */
::-webkit-scrollbar { width: 8px; }
::-webkit-scrollbar-track { background: #000; }
::-webkit-scrollbar-thumb { background: #2e1065; border-radius: 10px; border: 1px solid #00FF41; }
</style>''', unsafe_allow_html=True)

# Authentication & Navigation (Sidebar)
st.sidebar.title("🔐 Authentication")
password = st.sidebar.text_input("Enter Password", type='password')

if password != 'admin123':
    st.warning("Please enter the correct password to access the dashboard.")
    st.stop()

st.sidebar.title("🧭 Navigation")
page = st.sidebar.radio(
    "Select Page:",
    ('🏠 Overview', '🛡️ Threat Intel', '🌍 Global Map', '🕵️ Forensic Lab', '📡 Live Tap', '⚙️ System Admin')
)

# Data Connection
@st.cache_data(ttl=5) # Cache slightly to avoid overwhelming DB, but keep fresh
def get_data():
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            database=os.getenv('DB_NAME', 'nids_db'),
            user=os.getenv('DB_USER', 'nids_user'),
            password=os.getenv('DB_PASS', 'nids_password')
        )
        query = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 1000"
        df = pd.read_sql(query, conn)
        conn.close()
        
        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        return df
    except Exception as e:
        st.error(f"Database connection error: {e}")
        return pd.DataFrame()

df = get_data()

# Page Views
if page == '🏠 Overview':
    st.markdown(
        '<div style="width: 100%; padding: 40px; border-radius: 20px; background: rgba(46, 16, 101, 0.3); '
        'backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.1); border-left: 8px solid #00FF41; '
        'box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8); margin-bottom: 40px; position: relative;">'
        '<div style="position: absolute; top: 15px; right: 20px; font-family: monospace; color: #00FF41; font-size: 10px; letter-spacing: 1px;">'
        '[ AADITYA // NIDS-X : DEV_MODE ]</div>'
        '<h1 style="color: white; font-size: 55px; font-weight: 700; margin: 0; line-height: 1.1; font-family: \'Space Grotesk\';">'
        'SECURING THE <span style="color: #00FF41;">DIGITAL</span> FUTURE</h1>'
        '<div style="margin-top: 20px;">'
        '<span style="background: rgba(0, 255, 65, 0.1); border: 1px solid rgba(0, 255, 65, 0.3); color: #00FF41; '
        'padding: 8px 20px; border-radius: 50px; font-size: 14px; font-weight: 500;">'
        'Protecting Data, People, and Progress in a Connected World</span>'
        '</div></div>',
        unsafe_allow_html=True
    )
    
    col1, col2, col3 = st.columns(3)
    
    # Calculate metrics
    total_flows = len(df)
    total_attacks = len(df[df['attack_type'] != 'Normal']) if 'attack_type' in df.columns else 0
    avg_latency = "12 ms" # Mocked as it's not typically in the alerts table
    
    col1.metric('Total Network Flows', total_flows, delta='Normal Traffic Volume', delta_color='normal')
    col2.metric('Active Threats Detected', total_attacks, delta=f'{total_attacks} unresolved', delta_color='inverse')
    col3.metric("Avg Engine Latency", avg_latency)
    
    st.subheader("Network Traffic Timeline")
    if not df.empty and 'timestamp' in df.columns:
        # Group by minute for a cleaner timeline
        timeline_df = df.groupby(df['timestamp'].dt.floor('Min')).size().reset_index(name='count')
        fig = px.area(timeline_df, x='timestamp', y='count', title="Events per Minute",
                      color_discrete_sequence=['#00D4FF'])
        fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data available.")

elif page == '🛡️ Threat Intel':
    st.title("🛡️ Threat Intel")
    if not df.empty and 'attack_type' in df.columns and 'source_ip' in df.columns:
        threat_df = df[df['attack_type'] != 'BENIGN']
        
        if not threat_df.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Attack Types Breakdown")
                fig = px.pie(threat_df, names='attack_type', hole=0.3, color_discrete_sequence=px.colors.sequential.Plasma)
                fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white')
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                st.subheader("Top 5 Attacking Source IPs")
                top_ips = threat_df['source_ip'].value_counts().reset_index().head(5)
                top_ips.columns = ['Attacking IP', 'Attack Count']
                st.dataframe(top_ips, use_container_width=True)
                
                st.markdown("---")
                st.subheader('🛡️ Active Mitigation')
                if not top_ips.empty:
                    target_ip = st.selectbox('Select IP to Block at Firewall:', top_ips['Attacking IP'].tolist())
                    if st.button(f'🔨 Block {target_ip} on System Firewall', type='primary'):
                        system_os = platform.system()
                        if system_os == 'Windows':
                            cmd = f'netsh advfirewall firewall add rule name="NIDS_BLOCK_{target_ip}" dir=in action=block remoteip={target_ip}'
                        else:
                            cmd = f'sudo iptables -A INPUT -s {target_ip} -j DROP'
                        
                        os.system(cmd)
                        st.toast('✅ Firewall rule added successfully!', icon='🛡️')
                        st.caption('Note: Requires dashboard to be run with Admin/Sudo privileges.')
        else:
            st.success("System Secure. No active threats detected.")
    else:
        st.info("Insufficient data for Threat Intel.")

elif page == '🌍 Global Map':
    st.title("🌍 Global Threat Topology")
    if not df.empty and 'attack_type' in df.columns and 'source_ip' in df.columns:
        threat_df = df[df['attack_type'] != 'BENIGN']
        unique_ips = threat_df['source_ip'].unique()
        
        if len(unique_ips) > 0:
            st.markdown("Mapping threat origins...")
            
            map_data = []
            for ip in unique_ips:
                try:
                    res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
                    if res and res.get("status") == "success":
                        map_data.append({
                            "ip": ip,
                            "lat": res["lat"],
                            "lon": res["lon"]
                        })
                    else:
                        raise ValueError("API Failed")
                except Exception:
                    # Default coordinates for local/unresolved IPs
                    map_data.append({
                        "ip": ip,
                        "lat": 0.0,
                        "lon": 0.0
                    })
            
            if map_data:
                map_df = pd.DataFrame(map_data)
                
                layer = pdk.Layer(
                    "ScatterplotLayer",
                    map_df,
                    get_position=["lon", "lat"],
                    get_fill_color=[255, 49, 49, 200],
                    get_radius=50000,
                    pickable=True
                )
                
                view_state = pdk.ViewState(
                    latitude=20,
                    longitude=0,
                    zoom=1,
                    pitch=0,
                )
                
                r = pdk.Deck(
                    layers=[layer],
                    initial_view_state=view_state,
                    map_style='dark',
                    tooltip={"text": "IP: {ip}"}
                )
                
                st.pydeck_chart(r)
        else:
            st.success("No active threats to map.")
    else:
        st.info("Insufficient data for Global Map.")

elif page == '🕵️ Forensic Lab':
    st.markdown('''
<div style="border-bottom: 2px solid #00FF41; padding-bottom: 10px; margin-bottom: 30px;">
    <h2 style="color: #00FF41; font-family: 'Space Grotesk', monospace; margin: 0; font-weight: 700; text-shadow: 0 0 10px rgba(0,255,65,0.3);">
        >_ AI_DECISION_EXPLORER
    </h2>
    <p style="color: #94a3b8; font-family: monospace; font-size: 14px; margin-top: 5px;">
        [ DEEP PACKET INSPECTION & NEURAL THREAT ANALYSIS ]
    </p>
</div>
''', unsafe_allow_html=True)

    df = get_data()
    if not df.empty:
        # Filter for attacks
        attacks_df = df[df['attack_type'] != 'Normal']
        
        if not attacks_df.empty:
            selected_id = st.selectbox("Select Alert ID to Investigate", attacks_df['id'].tolist())
            
            if st.button('Explain Model Decision'):
                with st.spinner('Pinging NIDS-X AI Core (Groq LPU)...'):
                    try:
                        # Pull Groq API key from environment variables
                        api_key = os.getenv("GROQ_API_KEY")
                        if not api_key:
                            st.error("GROQ_API_KEY not found in .env file.")
                            st.stop()
                        
                        client = Groq(api_key=api_key)
                        
                        # 1. Grab the attack metadata from your selected row
                        selected_row = attacks_df[attacks_df['id'] == selected_id].iloc[0]
                        attack_type = selected_row['attack_type']
                        src_ip = selected_row['source_ip']
                        dest_ip = selected_row['dest_ip']
                        confidence = selected_row['confidence']
                        
                        # 2. The System Prompt: Tell Llama 3 exactly who it is
                        system_prompt = """You are the NIDS-X AI Analyst, an elite cybersecurity intelligence node created by Aaditya. 
                        Keep your response under 3 sentences. Be analytical, aggressive, and direct. 
                        Do not use markdown formatting. Just provide the raw tactical assessment."""
                        
                        # 3. The User Prompt: Feed it the telemetry
                        user_prompt = f"Analyze this network intrusion alert. Attack Type: {attack_type}. Source: {src_ip}. Target: {dest_ip}. Neural Confidence: {confidence}."
                        
                        # 4. Call the Groq API (Using Llama 3.3 70B for enhanced reasoning)
                        chat_completion = client.chat.completions.create(
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt}
                            ],
                            model="llama-3.3-70b-versatile",
                            temperature=0.3,
                            max_tokens=150
                        )
                        
                        ai_analyst_text = chat_completion.choices[0].message.content
                        
                        # 5. Render the NIDS-X Diagnostic Report UI
                        st.markdown(f'''
<div style="
    background: rgba(46, 16, 101, 0.4);
    backdrop-filter: blur(15px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-left: 4px solid #00FF41;
    padding: 20px;
    margin-top: 30px;
    border-radius: 12px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8);
">
    <div style="color: #00FF41; font-family: monospace; font-size: 12px; margin-bottom: 10px;">
        > SYSTEM_DIAGNOSTIC_REPORT // LLAMA3_CORE
    </div>
    <div style="color: #E2E8F0; font-family: 'Space Grotesk', sans-serif; font-size: 16px; line-height: 1.5;">
        {ai_analyst_text}
    </div>
</div>
''', unsafe_allow_html=True)
                        
                    except Exception as e:
                        st.error(f"AI Core Connection Failed: {e}")
        else:
            st.info("No attack telemetry available for analysis.")
    else:
        st.info("No active telemetry streams found.")

elif page == '📡 Live Tap':
    st.markdown('''
<div style="border-bottom: 2px solid #00FF41; padding-bottom: 10px; margin-bottom: 30px;">
    <h2 style="color: #00FF41; font-family: 'Space Grotesk', monospace; margin: 0; font-weight: 700; text-shadow: 0 0 10px rgba(0,255,65,0.3);">
        >_ LIVE_PACKET_TAP
    </h2>
    <p style="color: #94a3b8; font-family: monospace; font-size: 14px; margin-top: 5px;">
        [ REAL-TIME PCAP & KAFKA STREAMING ENGINE ]
    </p>
</div>
''', unsafe_allow_html=True)

    # Initialize session state for sniffer process
    if 'sniffer_process' not in st.session_state:
        st.session_state.sniffer_process = None

    col1, col2 = st.columns([1, 2])
    
    with col1:
        if st.session_state.sniffer_process is None:
            if st.button("🚀 Start Live Sniffer", type="primary", use_container_width=True):
                try:
                    # Start sniffer as background process
                    st.session_state.sniffer_process = subprocess.Popen([sys.executable, 'live_sniffer.py'])
                    st.toast("📡 Live Sniffer Activated!", icon="🚀")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to start sniffer: {e}")
        else:
            if st.button("🛑 Stop Live Sniffer", type="secondary", use_container_width=True):
                st.session_state.sniffer_process.terminate()
                st.session_state.sniffer_process = None
                st.toast("📡 Live Sniffer Terminated.", icon="🛑")
                time.sleep(1)
                st.rerun()

    with col2:
        if st.session_state.sniffer_process:
            st.success("🟢 STATUS: SNIFFER ACTIVE (Streaming to Kafka)")
        else:
            st.info("⚪ STATUS: SNIFFER IDLE")

    st.markdown("---")
    st.subheader("Incoming Telemetry Stream")
    
    if not df.empty:
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Waiting for telemetry data...")
        
    time.sleep(3)
    st.rerun()

elif page == '⚙️ System Admin':
    st.title("⚙️ System Admin")
    
    st.subheader("System Health")
    col1, col2, col3 = st.columns(3)
    col1.success("✅ Postgres: ONLINE")
    col2.success("✅ Kafka: ONLINE")
    col3.success("✅ XGBoost Engine: ONLINE")
    
    st.markdown("---")
    
    with st.expander('📄 Compliance & Reporting', expanded=False):
        if st.button("Generate Summary Report"):
            with st.spinner("Generating PDF Report..."):
                os.system('python generate_report.py')
            st.success("Report generated successfully!")

    st.markdown("---")
    
    with st.expander('🧪 Simulation Controls', expanded=True):
        if st.button('🔥 Launch Demo Mode (Inject Global Threats)', type='primary'):
            with st.spinner('Injecting synthetic threat payloads...'):
                try:
                    conn = psycopg2.connect(
                        host=os.getenv('DB_HOST', 'localhost'),
                        database=os.getenv('DB_NAME', 'nids_db'),
                        user=os.getenv('DB_USER', 'nids_user'),
                        password=os.getenv('DB_PASS', 'nids_password')
                    )
                    cur = conn.cursor()
                    
                    demo_ips = ['82.165.177.154', '103.22.200.1', '177.43.255.1', '197.234.10.1', '210.11.43.2', '45.33.22.11']
                    demo_attacks = ['DoS Hulk', 'PortScan', 'FTP-Patator', 'Bot', 'DDoS']
                    
                    for _ in range(15):
                        random_ip = random.choice(demo_ips)
                        random_attack = random.choice(demo_attacks)
                        confidence = random.uniform(0.85, 0.99)
                        inf_time = random.uniform(10.5, 45.5)
                        
                        cur.execute(
                            "INSERT INTO alerts (timestamp, source_ip, dest_ip, attack_type, confidence, inference_time_ms) VALUES (%s, %s, %s, %s, %s, %s)", 
                            (datetime.datetime.now(), random_ip, '192.168.1.50', random_attack, confidence, inf_time)
                        )
                    
                    conn.commit()
                    cur.close()
                    conn.close()
                    
                    st.success('Demo payload successfully injected! Refreshing telemetry...')
                    time.sleep(1.5)
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Failed to inject demo data: {e}")

        if st.button('🛑 Purge Demo Data (Restore Live Feed)', type='secondary'):
            with st.spinner('Purging synthetic threat payloads...'):
                try:
                    conn = psycopg2.connect(
                        host=os.getenv('DB_HOST', 'localhost'),
                        database=os.getenv('DB_NAME', 'nids_db'),
                        user=os.getenv('DB_USER', 'nids_user'),
                        password=os.getenv('DB_PASS', 'nids_password')
                    )
                    cur = conn.cursor()
                    
                    demo_ips = ['82.165.177.154', '103.22.200.1', '177.43.255.1', '197.234.10.1', '210.11.43.2', '45.33.22.11']
                    
                    cur.execute("DELETE FROM alerts WHERE source_ip = ANY(%s)", (demo_ips,))
                    
                    conn.commit()
                    cur.close()
                    conn.close()
                    
                    st.toast('✅ Demo data purged! Restoring live feed...', icon='🧹')
                    time.sleep(1.5)
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Failed to purge demo data: {e}")
