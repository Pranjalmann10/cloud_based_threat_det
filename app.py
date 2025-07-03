import pandas as pd
import streamlit as st
import plotly.express as px
from azure.storage.blob import BlobServiceClient
import json, io, requests, time
import os
from dotenv import load_dotenv

load_dotenv()
AZURE_CONN_STR = os.getenv("AZURE_CONN_STR")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ----------------------------
# CONFIGURATION
# ----------------------------
CONTAINER_NAME = "cowrielogs"
ENABLE_ABUSEIPDB = True  # Set to True to use AbuseIPDB
RISK_THRESHOLD = 50  # Risk score threshold to flag

# ----------------------------
# Load latest blob (Cowrie log)
# ----------------------------
@st.cache_data(ttl=60*5)
def fetch_latest_cowrie_log():
    blob_service = BlobServiceClient.from_connection_string(AZURE_CONN_STR)
    container_client = blob_service.get_container_client(CONTAINER_NAME)
    blobs = container_client.list_blobs()
    latest_blob = max(blobs, key=lambda b: b.last_modified)

    blob_client = container_client.get_blob_client(latest_blob.name)
    blob_data = blob_client.download_blob().readall()
    
    logs = []
    for line in blob_data.decode("utf-8").splitlines():
        try:
            logs.append(json.loads(line))
        except:
            continue
    return pd.DataFrame(logs)

# ----------------------------
# Optional: AbuseIPDB Enrichment
# ----------------------------
@st.cache_data(ttl=60*10)
def enrich_with_abuseipdb(ip_list):
    enriched = []
    for ip in ip_list:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            res = requests.get(url, headers=headers, params=params)
            data = res.json().get("data", {})
            enriched.append({
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "last_reported": data.get("lastReportedAt", "")
            })
            time.sleep(1.5)
        except Exception as e:
            enriched.append({"ip": ip, "abuse_score": 0})
    return pd.DataFrame(enriched)

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="CTDRP Dashboard", layout="wide")
st.title(" Real-Time Threat Dashboard - CTDRP")

with st.spinner(" Fetching latest log from Azure Blob..."):
    df = fetch_latest_cowrie_log()

# Filter events
df = df[df['eventid'].isin(['cowrie.login.failed', 'cowrie.login.success', 'cowrie.command.input'])].copy()
df['src_ip'] = df['src_ip'].fillna('')
df['command'] = df.get('input', '')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# ----------------------------
# Feature Engineering
# ----------------------------
# Brute force detection
fail_counts = df[df['eventid'] == 'cowrie.login.failed']['src_ip'].value_counts()
brute_ips = fail_counts[fail_counts > 5].index.tolist()
df['brute_force'] = df['src_ip'].isin(brute_ips)

# Dangerous commands
dangerous_cmds = ['wget', 'curl', 'chmod', 'nc', 'python', 'perl']
df['dangerous_command'] = df['command'].str.contains('|'.join(dangerous_cmds), case=False, na=False)

# Optional: AbuseIPDB lookup
abuse_df = pd.DataFrame()
if ENABLE_ABUSEIPDB:
    st.warning(" AbuseIPDB is enabled. This may take time and use your quota.")
    ip_list = df['src_ip'].unique().tolist()
    abuse_df = enrich_with_abuseipdb(ip_list)
    df = df.merge(abuse_df, how="left", left_on="src_ip", right_on="ip")
    df['abuse_score'] = df['abuse_score'].fillna(0)
else:
    df['abuse_score'] = 0

# Risk scoring
df['risk_score'] = (
    df['abuse_score'] * 0.5 +
    df['brute_force'].astype(int) * 30 +
    df['dangerous_command'].astype(int) * 20
)

df['flag'] = df['risk_score'] > RISK_THRESHOLD

# ----------------------------
# Dashboard UI
# ----------------------------
st.sidebar.header(" Filter Options")
min_risk = st.sidebar.slider("Minimum Risk Score", 0, 100, 50)
show_flagged = st.sidebar.checkbox("Show only flagged threats", True)

filtered = df[df['risk_score'] >= min_risk]
if show_flagged:
    filtered = filtered[filtered['flag'] == True]

col1, col2, col3 = st.columns(3)
col1.metric(" Total Events", len(df))
col2.metric(" Flagged Threats", len(df[df['flag'] == True]))
col3.metric(" Unique IPs", df['src_ip'].nunique())

st.subheader(" Top Attacker IPs")
st.bar_chart(filtered['src_ip'].value_counts().head(10))

st.subheader("⚔️ Most Frequent Commands")
st.bar_chart(filtered['command'].value_counts().head(10))

st.subheader(" Threat Log Table")
st.dataframe(filtered[['timestamp', 'src_ip', 'command', 'abuse_score', 'brute_force', 'dangerous_command', 'risk_score', 'flag']])
