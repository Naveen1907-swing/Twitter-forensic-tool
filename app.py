import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
import re
import ipaddress
import hashlib
from collections import defaultdict

# Set page configuration
st.set_page_config(
    page_title="Advanced Cybersecurity Forensics Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
    <style>
    .main {
        background-color: #1E1E1E;
    }
    .stAlert {
        background-color: #2E2E2E;
    }
    .metric-card {
        background-color: #2E2E2E;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Advanced Security Analysis Functions
def analyze_attack_patterns(df):
    """Analyze attack patterns and techniques"""
    attack_patterns = defaultdict(int)
    for technique in df['mitre_technique'].dropna():
        if technique != 'None':
            attack_patterns[technique] += 1
    return dict(attack_patterns)

def calculate_threat_score(row):
    """Calculate comprehensive threat score"""
    score = 0
    if row['is_malicious']:
        score += 40
    if row['known_bad_actor']:
        score += 20
    score += row['threat_feed_matches'] * 10
    if row['auth_status'] == 'Failed':
        score += 15
    return min(score, 100)

def analyze_network_behavior(df):
    """Analyze network behavior patterns"""
    suspicious_patterns = {
        'port_scanning': df['port'].nunique() > 10,
        'brute_force': len(df[df['auth_status'] == 'Failed']) > 5,
        'data_exfiltration': df['payload_size'].max() > 9000,
        'unusual_protocols': df['protocol'].value_counts().index[0] not in ['HTTP', 'HTTPS']
    }
    return suspicious_patterns

# Load and process data
@st.cache_data
def load_data():
    df = pd.read_csv('forensic_tweets.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Enhanced security analysis
    df['threat_score'] = df.apply(calculate_threat_score, axis=1)
    df['attack_severity'] = pd.qcut(df['threat_score'], 
                                  q=4, 
                                  labels=['Low', 'Medium', 'High', 'Critical'])
    return df

# Main Application
def main():
    st.title("🛡️ Advanced Cybersecurity Forensics Platform")
    st.subheader("Real-time Threat Detection and Analysis System")

    try:
        df = load_data()
        
        # Sidebar Controls
        st.sidebar.header("🎛️ Analysis Controls")
        date_range = st.sidebar.date_input(
            "Analysis Period",
            value=(df['timestamp'].min().date(), df['timestamp'].max().date())
        )
        
        severity_filter = st.sidebar.multiselect(
            "Threat Severity",
            ['Critical', 'High', 'Medium', 'Low'],
            default=['Critical', 'High']
        )
        
        # Filter data based on selections
        mask = (
            (df['timestamp'].dt.date >= date_range[0]) &
            (df['timestamp'].dt.date <= date_range[1]) &
            (df['attack_severity'].isin(severity_filter))
        )
        filtered_df = df[mask]

        # Security Overview Dashboard
        st.header("🎯 Security Overview Dashboard")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            critical_threats = len(filtered_df[filtered_df['attack_severity'] == 'Critical'])
            st.metric("Critical Threats", critical_threats,
                     delta=critical_threats - len(df[df['attack_severity'] == 'Critical']))
        
        with col2:
            active_attackers = filtered_df[filtered_df['known_bad_actor']]['username'].nunique()
            st.metric("Active Attackers", active_attackers)
        
        with col3:
            avg_threat_score = filtered_df['threat_score'].mean()
            st.metric("Average Threat Score", f"{avg_threat_score:.1f}")
        
        with col4:
            blocked_attacks = len(filtered_df[filtered_df['action_taken'] == 'Blocked'])
            st.metric("Blocked Attacks", blocked_attacks)

        # Advanced Analysis Tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🎯 Attack Analysis",
            "🌐 Network Security",
            "👤 User Behavior",
            "🔍 Threat Intelligence",
            "📊 MITRE ATT&CK"
        ])
        
        with tab1:
            st.subheader("Attack Pattern Analysis")
            
            # Attack Timeline
            fig = px.line(filtered_df, x='timestamp', y='threat_score',
                         color='attack_severity',
                         title='Threat Score Timeline')
            st.plotly_chart(fig, use_container_width=True)
            
            # Attack Distribution
            attack_dist = filtered_df['attack_type'].value_counts()
            fig = px.pie(values=attack_dist.values, names=attack_dist.index,
                        title='Attack Type Distribution')
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            st.subheader("Network Security Analysis")
            
            # Protocol Analysis
            protocol_dist = filtered_df['protocol'].value_counts()
            fig = px.bar(x=protocol_dist.index, y=protocol_dist.values,
                        title='Protocol Distribution')
            st.plotly_chart(fig, use_container_width=True)
            
            # Port Analysis
            port_dist = filtered_df['port'].value_counts().head(10)
            st.bar_chart(port_dist)
            
            # Suspicious Network Patterns
            network_patterns = analyze_network_behavior(filtered_df)
            st.write("### Suspicious Network Patterns Detected")
            for pattern, detected in network_patterns.items():
                st.warning(f"{pattern}: {'Detected' if detected else 'Not Detected'}")
        
        with tab3:
            st.subheader("User Behavior Analysis")
            
            # Authentication Analysis
            auth_dist = filtered_df['auth_status'].value_counts()
            fig = px.pie(values=auth_dist.values, names=auth_dist.index,
                        title='Authentication Status Distribution')
            st.plotly_chart(fig, use_container_width=True)
            
            # High-Risk Users
            high_risk = filtered_df[filtered_df['attack_severity'] == 'Critical']
            st.write("### High-Risk Users")
            st.dataframe(high_risk[['username', 'threat_score', 'attack_type', 'action_taken']])
        
        with tab4:
            st.subheader("Threat Intelligence")
            
            # Threat Feed Analysis
            st.write("### Threat Feed Matches")
            threat_feed = filtered_df[filtered_df['threat_feed_matches'] > 0]
            fig = px.scatter(threat_feed, x='timestamp', y='threat_feed_matches',
                           size='threat_score', color='attack_severity',
                           hover_data=['username', 'attack_type'])
            st.plotly_chart(fig, use_container_width=True)
            
            # Known Bad Actors
            st.write("### Known Bad Actors")
            bad_actors = filtered_df[filtered_df['known_bad_actor']]
            st.dataframe(bad_actors[['username', 'country', 'attack_type', 'threat_score']])
        
        with tab5:
            st.subheader("MITRE ATT&CK Analysis")
            
            # MITRE Technique Distribution
            mitre_dist = filtered_df['mitre_technique'].value_counts()
            fig = px.bar(x=mitre_dist.index, y=mitre_dist.values,
                        title='MITRE ATT&CK Technique Distribution')
            st.plotly_chart(fig, use_container_width=True)
            
            # Attack Pattern Analysis
            attack_patterns = analyze_attack_patterns(filtered_df)
            st.write("### Attack Patterns")
            st.json(attack_patterns)

        # Real-time Monitoring
        st.sidebar.header("🔴 Real-time Monitoring")
        if st.sidebar.button("Enable Real-time Monitoring"):
            st.sidebar.markdown("""
                ### Active Monitoring
                - Monitoring Status: **Active**
                - Last Updated: **{}**
                - Active Threats: **{}**
                - Current Threat Level: **{}**
            """.format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                critical_threats,
                "High" if avg_threat_score > 70 else "Medium"
            ))

        # Export Options
        st.sidebar.header("📤 Export Options")
        if st.sidebar.button("Generate Detailed Report"):
            report_data = {
                'Analysis Period': f"{date_range[0]} to {date_range[1]}",
                'Total Events Analyzed': len(filtered_df),
                'Critical Threats': critical_threats,
                'Active Attackers': active_attackers,
                'Average Threat Score': f"{avg_threat_score:.1f}",
                'Blocked Attacks': blocked_attacks,
                'Most Common Attack Type': attack_dist.index[0],
                'Most Targeted Protocol': protocol_dist.index[0]
            }
            
            report_df = pd.DataFrame(list(report_data.items()), 
                                   columns=['Metric', 'Value'])
            csv = report_df.to_csv(index=False)
            
            st.sidebar.download_button(
                label="Download Security Report",
                data=csv,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    except Exception as e:
        st.error(f"Error in analysis: {str(e)}")
        st.write("Please check the data source and try again.")

if __name__ == "__main__":
    main()
