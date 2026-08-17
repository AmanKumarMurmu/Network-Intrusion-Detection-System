"""Optional offline Streamlit dashboard over the local SQLite event store."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from storage import DB_PATH, connect

st.set_page_config(page_title="Sentinel NIDS (local)", layout="wide")
st.title("Sentinel NIDS — local sensor view")

conn = connect(DB_PATH)
df = pd.read_sql_query(
    "SELECT occurred_at, src_ip, dst_ip, protocol, verdict, attack_type,"
    " risk_level, confidence, packet_count, byte_count"
    " FROM security_events ORDER BY occurred_at DESC LIMIT 2000",
    conn,
)

if df.empty:
    st.info("No events yet — start nids_agent.py to begin capturing traffic.")
    st.stop()

df["occurred_at"] = pd.to_datetime(df["occurred_at"], errors="coerce", utc=True)
attacks = df[df["verdict"] == "attack"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Flows analyzed", len(df))
c2.metric("Attacks", len(attacks))
c3.metric("Critical", int((attacks["risk_level"] == "critical").sum()))
c4.metric("Hostile IPs", attacks["src_ip"].nunique())

st.subheader("Attack trend (hourly)")
if not attacks.empty:
    trend = attacks.set_index("occurred_at").resample("1h").size().rename("attacks")
    st.line_chart(trend)

st.subheader("Attacks by category")
if not attacks.empty:
    st.bar_chart(attacks["attack_type"].value_counts())

st.subheader("Security event log")
st.dataframe(df, width="stretch", hide_index=True)
