# LLM-Powered Intrusion Detection System

Live packet capture via Scapy, flow summarization, and a local LLM that
classifies each network flow as **Benign**, **Suspicious**, or **Attack**
with a plain-English explanation — shown on a live Streamlit dashboard.

## Architecture

```
Network Interface → Scapy Sniffer → Packet Collection → Flow Generator
        → Feature Extraction (Statistics / Protocol Info / Flags)
        → Flow Summary → Local LLM Analyzer → Classification + Explanation
        → SQLite → Streamlit Dashboard
```

The detection pipeline (`main.py`) and the dashboard (`dashboard/app.py`)
are fully decoupled — they only communicate through `storage/flows.db`.
That means the dashboard can be rebuilt in something else entirely later
without touching any detection logic.

## Install

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

You also need **Ollama** (not a pip package) to run the local model:

1. Install it from https://ollama.com
2. Pull a model: `ollama pull llama3.1:8b` (or `mistral` / `phi3` for something lighter)
3. Ollama serves itself at `http://localhost:11434` automatically after install

**Packet capture requires elevated privileges:**
- Linux/macOS: run with `sudo`
- Windows: install [Npcap](https://npcap.com/) and run your terminal as Administrator

## Run

Two terminals:

```bash
# Terminal 1 — the detection pipeline
sudo python3 main.py

# Terminal 2 — the dashboard
streamlit run dashboard/app.py
```

Generate some traffic (browse the web, `ping`, etc.) and watch flows appear
on the dashboard within a few seconds of each connection closing.

## Tests

```bash
python3 tests/test_flow_tracker.py
```

## Project structure

```
llm-ids/
├── sniffer/
│   ├── capture.py        # Scapy sniffer
│   └── flow_tracker.py   # 5-tuple grouping, timeout logic
├── features/
│   └── extractor.py      # stats, protocol info, flags
├── analyzer/
│   ├── prompt_builder.py # flow → structured prompt
│   └── llm_client.py     # Ollama API calls
├── storage/
│   └── db.py             # SQLite results store
├── dashboard/
│   └── app.py            # Streamlit viewer
├── tests/
├── config.py
├── requirements.txt
└── README.md
```

## Design notes

- **Fail-safe LLM errors**: if the Ollama call fails or returns malformed
  JSON, the flow is marked `Suspicious` rather than silently dropped or
  marked `Benign` — an IDS should never go quiet on error.
- **Bidirectional flow keying**: both directions of one TCP/UDP
  conversation map to the same flow, so request and response packets are
  analyzed together.
- **Flow close conditions**: a flow ends either on a `FIN`/`RST` packet
  or after `FLOW_TIMEOUT_SECONDS` of inactivity (configurable in `config.py`).