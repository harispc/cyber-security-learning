# Notebook-friendly Suricata report
# Paste this entire cell into a Jupyter Notebook and run.
# By default it looks for "alerts-only.json" in the notebook folder.
# If not present, it can download the sample from GitHub.

import os
import json
from collections import Counter
from datetime import datetime
from dateutil import parser as dateparser

import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display, HTML
from jinja2 import Template

# Ensure plots render inline
%matplotlib inline

# ---------- Config ----------
DEFAULT_JSON = "alerts-only.json"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/FrankHassanabad/suricata-sample-data/master/samples/wrccdc-2018/alerts-only.json"
OUTDIR = "report_output"

# ---------- Helpers ----------
def download_if_missing(path=DEFAULT_JSON, url=GITHUB_RAW_URL, force=False):
    if os.path.exists(path) and not force:
        print(f"Found local file: {path}")
        return path
    try:
        import requests
        print(f"Downloading {url} ...")
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(path, "wb") as f:
            f.write(r.content)
        print(f"Saved to {path}")
        return path
    except Exception as e:
        print("Download failed:", e)
        return None

def load_suricata_json(path):
    """Load either JSON array or newline-delimited JSON."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
        if not text:
            return []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                items.append(json.loads(s))
            except json.JSONDecodeError:
                continue
    return items

def safe_get(d, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur

def build_dataframe(records):
    rows = []
    for r in records:
        et = r.get("event_type") or r.get("type")
        # prefer processing alerts only (defensive)
        if et and "alert" not in str(et).lower():
            continue

        ts_raw = r.get("timestamp") or r.get("ts") or r.get("time")
        try:
            ts = dateparser.parse(ts_raw) if ts_raw else pd.NaT
        except Exception:
            ts = pd.NaT

        alert = r.get("alert", {}) if isinstance(r.get("alert", {}), dict) else {}
        signature = alert.get("signature") or alert.get("msg") or ""
        sig_id = alert.get("signature_id") or alert.get("sid") or ""
        category = alert.get("category") or alert.get("class") or ""
        severity = alert.get("severity") if alert.get("severity") is not None else alert.get("severity_level")

        src_ip = r.get("src_ip") or safe_get(r, "source", "ip") or safe_get(r, "src", "ip")
        src_port = r.get("src_port") or safe_get(r, "source", "port") or r.get("sport")
        dst_ip = r.get("dest_ip") or safe_get(r, "destination", "ip") or safe_get(r, "dst", "ip")
        dst_port = r.get("dest_port") or safe_get(r, "destination", "port") or r.get("dport")

        rows.append({
            "timestamp": ts,
            "timestamp_raw": ts_raw,
            "signature": signature,
            "signature_id": sig_id,
            "category": category,
            "severity": severity,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "raw": r
        })
    df = pd.DataFrame(rows)
    # normalize timestamp dtype
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df

# ---------- Plot & Report ----------
def make_plots(df, outdir=OUTDIR, show_inline=True):
    os.makedirs(outdir, exist_ok=True)
    images = {}
    if df.empty:
        print("Empty dataframe — no plots created.")
        return images

    # Top signatures
    top_sigs = df['signature'].fillna("(empty)").value_counts().head(20)
    plt.figure(figsize=(10,6))
    top_sigs[::-1].plot.barh()
    plt.xlabel("Count")
    plt.title("Top 20 Alert Signatures")
    plt.tight_layout()
    sig_path = os.path.join(outdir, "top_signatures.png")
    plt.savefig(sig_path)
    if show_inline:
        display(plt.gcf())
    plt.close()
    images['top_signatures'] = sig_path

    # Top source IPs
    top_src = df['src_ip'].fillna("(unknown)").value_counts().head(20)
    plt.figure(figsize=(10,6))
    top_src[::-1].plot.barh()
    plt.xlabel("Count")
    plt.title("Top 20 Source IPs")
    plt.tight_layout()
    src_path = os.path.join(outdir, "top_src_ips.png")
    plt.savefig(src_path)
    if show_inline:
        display(plt.gcf())
    plt.close()
    images['top_src_ips'] = src_path

    # timeline (alerts per hour)
    if df['timestamp'].notnull().any():
        df_time = df[df['timestamp'].notnull()].copy()
        df_time['hour'] = df_time['timestamp'].dt.floor('H')
        times = df_time['hour'].value_counts().sort_index()
        plt.figure(figsize=(12,4))
        times.plot()
        plt.xlabel("Time (hour)")
        plt.ylabel("Alerts")
        plt.title("Alerts Timeline (per hour)")
        plt.tight_layout()
        t_path = os.path.join(outdir, "alerts_timeline.png")
        plt.savefig(t_path)
        if show_inline:
            display(plt.gcf())
        plt.close()
        images['alerts_timeline'] = t_path

    # severity pie
    if 'severity' in df.columns and df['severity'].notnull().any():
        sev_counts = df['severity'].fillna("unknown").astype(str).value_counts()
        plt.figure(figsize=(6,6))
        sev_counts.plot.pie(autopct="%1.1f%%", ylabel="")
        plt.title("Severity Distribution")
        plt.tight_layout()
        sev_path = os.path.join(outdir, "severity_pie.png")
        plt.savefig(sev_path)
        if show_inline:
            display(plt.gcf())
        plt.close()
        images['severity_pie'] = sev_path

    return images

def build_html_report(summary, images, outdir=OUTDIR, outname="summary_report.html"):
    os.makedirs(outdir, exist_ok=True)
    template = Template("""
    <html>
    <head><meta charset="utf-8"><title>Suricata Alerts Summary</title></head>
    <body style="font-family: sans-serif;">
      <h1>Suricata Alerts Summary</h1>
      <p>Generated: {{ generated }}</p>
      <h2>Overview</h2>
      <ul>
        <li>Total alerts processed: <strong>{{ total_alerts }}</strong></li>
        <li>Unique signatures: <strong>{{ unique_signatures }}</strong></li>
        <li>Unique source IPs: <strong>{{ unique_src_ips }}</strong></li>
        <li>Time range: <strong>{{ time_range }}</strong></li>
      </ul>

      <h2>Top Signatures</h2>
      {% if images.top_signatures %}<img src="{{ images.top_signatures }}" style="max-width:100%;height:auto;">{% else %}<p>No signature image</p>{% endif %}

      <h2>Top Source IPs</h2>
      {% if images.top_src_ips %}<img src="{{ images.top_src_ips }}" style="max-width:100%;height:auto;">{% endif %}

      <h2>Alerts Timeline</h2>
      {% if images.alerts_timeline %}<img src="{{ images.alerts_timeline }}" style="max-width:100%;height:auto;">{% else %}<p>No timeline available</p>{% endif %}

      <h2>Severity Distribution</h2>
      {% if images.severity_pie %}<img src="{{ images.severity_pie }}" style="max-width:320px;height:auto;">{% else %}<p>No severity data</p>{% endif %}

      <h2>Top 20 Signatures (table)</h2>
      <table border="1" cellpadding="6" cellspacing="0">
        <thead><tr><th>Signature</th><th>Count</th></tr></thead>
        <tbody>
        {% for sig,count in top_signatures %}
          <tr><td style="max-width:800px">{{ sig }}</td><td>{{ count }}</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </body>
    </html>
    """)
    html = template.render(
        generated = datetime.utcnow().isoformat() + "Z",
        total_alerts = summary['total_alerts'],
        unique_signatures = summary['unique_signatures'],
        unique_src_ips = summary['unique_src_ips'],
        time_range = summary['time_range'],
        images = images,
        top_signatures = summary['top_signatures_list']
    )
    outpath = os.path.join(outdir, outname)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    return outpath

# ---------- Main flow for notebook ----------
def notebook_report(json_path=None, download_if_missing_flag=True, show_inline=True):
    if json_path is None:
        json_path = DEFAULT_JSON

    if not os.path.exists(json_path):
        if download_if_missing_flag:
            got = download_if_missing(json_path)
            if not got:
                raise FileNotFoundError(f"File not found and download failed: {json_path}")
        else:
            raise FileNotFoundError(json_path)

    print("Loading", json_path)
    records = load_suricata_json(json_path)
    print(f"Loaded {len(records)} records")
    df = build_dataframe(records)
    print(f"Processed {len(df)} alert rows into DataFrame")

    # quick summary
    total_alerts = len(df)
    unique_signatures = int(df['signature'].nunique(dropna=True)) if not df.empty else 0
    unique_src_ips = int(df['src_ip'].nunique(dropna=True)) if not df.empty else 0
    ts_nonnull = df['timestamp'].dropna()
    if not ts_nonnull.empty:
        tmin = ts_nonnull.min().isoformat()
        tmax = ts_nonnull.max().isoformat()
        time_range = f"{tmin} to {tmax}"
    else:
        time_range = "No valid timestamps"

    top_sigs_list = [(s, int(c)) for s, c in df['signature'].fillna("(empty)").value_counts().head(20).items()]

    summary = {
        "total_alerts": total_alerts,
        "unique_signatures": unique_signatures,
        "unique_src_ips": unique_src_ips,
        "time_range": time_range,
        "top_signatures_list": top_sigs_list
    }

    # show summary
    display(HTML(f"<h2>Summary: {total_alerts} alerts | {unique_signatures} signatures | {unique_src_ips} src IPs</h2>"))
    display(HTML(f"<p>Time range: <strong>{time_range}</strong></p>"))

    # show sample of top signatures
    display(pd.DataFrame(top_sigs_list, columns=["signature","count"]))

    # plots (also saved)
    images = make_plots(df, outdir=OUTDIR, show_inline=show_inline)

    # save detailed CSV
    os.makedirs(OUTDIR, exist_ok=True)
    df['sig_count'] = df['signature'].map(lambda s: df['signature'].fillna("(empty)").value_counts().get(s,0))
    df_sorted = df.sort_values(['sig_count'], ascending=False)
    csv_path = os.path.join(OUTIR := OUTDIR, "detailed_threats.csv")
    df_sorted[['timestamp_raw','signature','signature_id','category','severity','src_ip','src_port','dst_ip','dst_port']].to_csv(csv_path, index=False)
    print("Saved detailed CSV to:", csv_path)

    # html report
    html_path = build_html_report(summary, images, outdir=OUTDIR)
    print("Saved HTML report to:", html_path)

    # show top 20 alerts table inline
    if not df_sorted.empty:
        display(df_sorted.head(50)[['timestamp_raw','signature','signature_id','category','severity','src_ip','dst_ip']])

    return {
        "dataframe": df,
        "images": images,
        "csv": csv_path,
        "html": html_path
    }

# ---------- Run it (default) ----------
# If you want to use a different filename, call notebook_report("path/to/file.json")
result = notebook_report(download_if_missing_flag=True, show_inline=True)
