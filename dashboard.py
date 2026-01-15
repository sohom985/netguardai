"""
NetGuardAI Dashboard - Rebuilt from scratch
Based on working dashboard_simple.py approach
"""
import streamlit as st
import sqlite3
import pandas as pd
import time
from security import scan_dataframe
from ml_detector import predict
from chatbot import chat


# Page Config
st.set_page_config(
    page_title="NetGuardAI Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ NetGuardAI - Real-Time Monitor")

# Sidebar Controls
st.sidebar.header("Controls")
use_live_mode = st.sidebar.checkbox("🔴 Live Monitoring Mode")

if st.sidebar.button("Refresh Now 🔄"):
    st.rerun()

st.sidebar.write(f"Last Update: {time.strftime('%H:%M:%S')}")

# Data Loading (Direct SQL - proven to work!)
@st.cache_data(ttl=3)
def load_data():
    try:
        conn = sqlite3.connect("netguard.db", timeout=5)
        df = pd.read_sql("SELECT * FROM traffic ORDER BY id DESC LIMIT 500", conn)
        conn.close()
        # Convert timestamp
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"DB Error: {e}")
        return pd.DataFrame()

# Load Data
df = load_data()

# Main Content
if df.empty:
    st.warning("⚠️ No data found! Please run 'sniffer.py' in a separate terminal.")
else:
    # KPI Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Packets", len(df))
    col2.metric("Unique Sources", df['src_ip'].nunique())
    col3.metric("Protocols", df['protocol'].nunique())
    col4.metric("Avg Packet Size", f"{df['length'].mean():.0f} bytes")
    
    # Data Table
    st.subheader("📡 Live Traffic Feed")
    st.dataframe(df.head(20), use_container_width=True)
    
    # Charts Section
    st.markdown("---")
    st.subheader("📊 Traffic Analytics")
    
    chart1, chart2 = st.columns(2)
    
    with chart1:
        st.write("**Protocol Distribution**")
        if 'protocol' in df.columns:
            st.bar_chart(df['protocol'].value_counts())
    
    with chart2:
        st.write("**Packet Sizes**")
        if 'length' in df.columns:
            st.bar_chart(df['length'].head(50))
            # 🛡️ Security Scan Section
    st.markdown("---")
    st.subheader("🛡️ Security Threat Detection")
    
    # Scan for attacks
    df_scanned = scan_dataframe(df)
    threats = df_scanned[df_scanned['threat_type'] != 'Normal']
    
    if len(threats) > 0:
        st.error(f"⚠️ Detected {len(threats)} suspicious packets!")
        st.dataframe(threats[['timestamp', 'src_ip', 'dst_ip', 'threat_type']], use_container_width=True)
    else:
        st.success("✅ No attack patterns detected in current traffic.")
    
    # 🔐 VPN Detection Section
    st.markdown("---")
    st.subheader("🔐 VPN Detection")
    
    from vpn_detector import detect_vpn, get_traffic_diversity_score
    
    vpn_result = detect_vpn(df)
    diversity_score = get_traffic_diversity_score(df)
    
    col_vpn1, col_vpn2 = st.columns(2)
    
    with col_vpn1:
        if vpn_result['vpn_detected']:
            confidence = vpn_result['confidence']
            if confidence == 'High':
                st.error(f"🚨 VPN Detected (Confidence: {confidence})")
            elif confidence == 'Medium':
                st.warning(f"⚠️ Possible VPN (Confidence: {confidence})")
            else:
                st.info(f"🔍 VPN Indicators Found (Confidence: {confidence})")
            
            # Show details
            if vpn_result['vpn_server_ip']:
                st.write(f"**Suspected VPN Server:** `{vpn_result['vpn_server_ip']}`")
            if vpn_result['vpn_type']:
                st.write(f"**VPN Protocol:** {vpn_result['vpn_type']}")
        else:
            st.success("✅ No VPN detected - traffic appears normal")
    
    with col_vpn2:
        st.metric("Traffic Diversity Score", f"{diversity_score:.1f}%", 
                  help="Higher = more diverse destinations (normal). Lower = concentrated (VPN-like)")
        
        if vpn_result['indicators']:
            with st.expander("📋 Detection Details"):
                for indicator in vpn_result['indicators']:
                    st.write(f"• {indicator}")
    
    # 🧠 ML Anomaly Detection Section
    st.markdown("---")
    st.subheader("🧠 ML Anomaly Detection")
    
    # Run ML predictions
    df_ml = predict(df)
    anomalies = df_ml[df_ml['ml_prediction'] == '🔴 Anomaly']
    
    col_a, col_b = st.columns(2)
    col_a.metric("🟢 Normal", len(df_ml) - len(anomalies))
    col_b.metric("🔴 Anomalies", len(anomalies))
    
    if len(anomalies) > 0:
        st.warning(f"🔴 Found {len(anomalies)} anomalous packets!")
        st.dataframe(anomalies[['timestamp', 'src_ip', 'length', 'anomaly_score']].head(10), use_container_width=True)
    else:
        st.success("✅ All traffic looks normal to the ML model!")

    # 🌍 Geolocation Map Section
    st.markdown("---")
    st.subheader("🌍 Geolocation Map")
    st.caption("Geographic locations of packet sources and destinations")
    
    from enrichment import get_ip_info, is_local_ip
    
    @st.cache_data(ttl=300)  # Cache for 5 minutes to avoid API rate limits
    def get_all_ip_data(ips):
        """Fetch geolocation for all IPs, showing N/A for private ones."""
        all_data = []
        public_data = []  # For map plotting
        
        for ip in ips[:30]:  # Limit to 30 IPs
            if is_local_ip(ip):
                all_data.append({
                    'IP Address': ip,
                    'Type': '🔒 Private',
                    'Country': 'N/A',
                    'City': 'N/A',
                    'ISP': 'Local Network',
                    'lat': None,
                    'lon': None
                })
            else:
                info = get_ip_info(ip)
                all_data.append({
                    'IP Address': ip,
                    'Type': '🌐 Public',
                    'Country': info.get('country', 'Unknown'),
                    'City': info.get('city', 'Unknown'),
                    'ISP': info.get('isp', 'Unknown'),
                    'lat': info.get('lat'),
                    'lon': info.get('lon')
                })
                if info.get('lat') and info.get('lon'):
                    public_data.append({
                        'lat': info['lat'],
                        'lon': info['lon'],
                        'ip': ip,
                        'country': info['country'],
                        'city': info['city']
                    })
        return all_data, public_data
    
    # Get unique destination IPs
    unique_ips = df['dst_ip'].unique().tolist()
    all_ip_data, public_geo_data = get_all_ip_data(unique_ips)
    
    # Show the IP table first
    st.write("**📋 IP Address Details**")
    ip_df = pd.DataFrame(all_ip_data)
    st.dataframe(
        ip_df[['IP Address', 'Type', 'Country', 'City', 'ISP']],
        use_container_width=True,
        hide_index=True
    )
    
    # Show map if we have public IP data
    if public_geo_data:
        st.write("**🗺️ Public IP Locations**")
        geo_df = pd.DataFrame(public_geo_data)
        st.map(geo_df, latitude='lat', longitude='lon', size=50)
        
        # Show country breakdown
        st.write("**📊 Country Breakdown**")
        country_counts = geo_df['country'].value_counts()
        st.bar_chart(country_counts)
    else:
        st.info("ℹ️ No public IPs detected yet. All current traffic is from private/local network addresses.")

# 🤖 AI Chatbot Section (Always visible)
st.markdown("---")
st.subheader("🤖 AI Security Assistant")
st.caption("Ask questions about your network traffic. Powered by Ollama.")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask about your network traffic..."):
    # Add user message to history
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    
    # Get AI response
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            response = chat(prompt)
        st.markdown(response)
    
    # Add assistant response to history
    st.session_state.messages.append({"role": "assistant", "content": response})

# Live Mode Logic (MUST be at the end!)
if use_live_mode:
    time.sleep(3)
    st.rerun()