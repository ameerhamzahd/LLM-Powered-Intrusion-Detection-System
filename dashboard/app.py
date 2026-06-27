"""Streamlit dashboard — a pure viewer over the results database. It never
touches the sniffer or the LLM directly, only reads what main.py wrote.

Run with: streamlit run dashboard/app.py
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.append(str(Path(__file__).resolve().parent.parent))  # allow `import storage.db`
from storage import db

st.set_page_config(page_title="LLM-IDS", layout="wide")
st.title("LLM-Powered Intrusion Detection")

if st.button("Refresh"):
    st.rerun()

db.init_db()
results = db.get_recent_results(limit=200)

if not results:
    st.info("No flows analyzed yet. Make sure main.py is running and capturing traffic.")
else:
    df = pd.DataFrame(results)
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

    counts = df["classification"].value_counts()
    col1, col2, col3 = st.columns(3)
    col1.metric("Benign", int(counts.get("Benign", 0)))
    col2.metric("Suspicious", int(counts.get("Suspicious", 0)))
    col3.metric("Attack", int(counts.get("Attack", 0)))

    def highlight(row):
        color = {
            "Benign": "#1e3d2f",
            "Suspicious": "#4d3b14",
            "Attack": "#4d1f1f",
        }.get(row["classification"], "")
        return [f"background-color: {color}"] * len(row)

    display_cols = ["timestamp", "flow_id", "classification", "confidence", "explanation"]
    st.dataframe(
        df[display_cols].style.apply(highlight, axis=1),
        use_container_width=True,
        height=600,
    )