import warnings
warnings.filterwarnings("ignore")
from flask import Flask, render_template, request, jsonify
import xml.etree.ElementTree as ET
import pandas as pd
import joblib
import os
import re

app = Flask(__name__)

# ---------------- LOAD MODELS ---------------- #
rf_model  = joblib.load("random_forest_model.pkl")
xgb_model = joblib.load("xgboost_model.pkl")
iso_model = joblib.load("isolation_forest_model.pkl")
scaler = joblib.load("scaler.pkl")
feature_columns = joblib.load("feature_columns.pkl")

# ---------------- FOLDER ---------------- #
if not os.path.exists("uploads"):
    os.makedirs("uploads")

# ---------------- GLOBAL STATS ---------------- #
scan_stats = {
    "files_scanned": 0,
    "safe_files": 0,
    "threats_detected": 0,
}

# ---------------- LOAD SYSMON (FINAL FIXED) ---------------- #
def load_sysmon(xml_path):
    with open(xml_path, "r", encoding="utf-8-sig") as f:
        content = f.read()

    if len(content.strip()) == 0:
        return {}

    content = re.sub(r'<\?xml[^>]+\?>', '', content).strip()

    try:
        root = ET.fromstring(content)
    except:
        try:
            content = "<Events>" + content + "</Events>"
            root = ET.fromstring(content)
        except:
            print("Invalid XML")
            return {}

    event_count = {}
    thread_counts = []
    handle_counts = []
    dll_names = set()
    injection_count = 0
    service_count = 0

    # 🔥 STRICT EVENT PARSING (FINAL FIX)
    for event in root:
        if "Event" not in event.tag:
            continue

        eid = None
        data = {}

        for child in event:

            # ---- SYSTEM ----
            if "System" in child.tag:
                for sub in child:
                    if "EventID" in sub.tag:
                        try:
                            eid = int(sub.text)
                            event_count[eid] = event_count.get(eid, 0) + 1
                        except:
                            pass

            # ---- EVENT DATA ----
            if "EventData" in child.tag:
                for sub in child:
                    if "Data" in sub.tag:
                        name = sub.attrib.get("Name")
                        value = sub.text
                        if name and value:
                            data[name] = value

        # -------- FEATURE LOGIC -------- #
        if eid == 1:
            try:
                thread_counts.append(int(data.get("NumberOfThreads", "0")))
            except:
                thread_counts.append(0)

        if eid == 7:
            dll = data.get("ImageLoaded", "")
            if dll:
                dll_names.add(dll.lower())

        if eid == 8:
            injection_count += 1

        if eid == 10:
            handle_counts.append(1)

        if eid == 13:
            service_count += 1

    # -------- FINAL COUNTS -------- #
    event_count["avg_threads"] = (sum(thread_counts) / len(thread_counts)) if thread_counts else 0
    event_count["avg_handlers"] = len(handle_counts) / max(event_count.get(1, 1), 1)
    event_count["dll_count_real"] = len(dll_names)
    event_count["injection_count"] = injection_count
    event_count["service_count"] = service_count

    print("EVENT COUNT:", event_count)  # 🔥 DEBUG

    return event_count

# ---------------- FEATURE EXTRACTION ---------------- #
def extract_features(event_count):
    process_count   = event_count.get(1, 0)
    dll_events      = event_count.get(7, 0)
    handle_events   = event_count.get(10, 0)
    network_events  = event_count.get(3, 0)
    registry_events = event_count.get(13, 0)

    avg_threads   = event_count.get("avg_threads", 0)
    avg_handlers  = event_count.get("avg_handlers", 0)
    dll_count     = event_count.get("dll_count_real", dll_events)
    injections    = event_count.get("injection_count", 0)
    service_count = event_count.get("service_count", 0)

    # 🔥 FIXED TOTAL (ONLY USEFUL EVENTS)
    useful_ids = [1, 3, 7, 8, 10, 13]
    total = sum(event_count.get(i, 0) for i in useful_ids)

    return {
        "process_count": process_count,
        "parent_process_count": process_count,
        "avg_threads": avg_threads,
        "avg_handlers": avg_handlers,
        "dll_count": dll_count,
        "dlls_per_process": dll_count / (process_count + 1),
        "handles_total": handle_events * 5,
        "handles_avg": avg_handlers / (process_count + 1),
        "service_count": service_count,
        "process_services": registry_events * 2,
        "mal_injections": injections,
        "mal_commit_charge": network_events * 1,
        "total_activity": total,
        "process_density": process_count / (total + 1),
        "handle_density": (handle_events * 5) / (process_count + 1),
    }

# ---------------- DATAFRAME ---------------- #
def build_scaled_df(features):
    df = pd.DataFrame([features])

    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    df = df[feature_columns]
    df_scaled = scaler.transform(df)

    return pd.DataFrame(df_scaled, columns=feature_columns)

# ---------------- ML ---------------- #
def ml_prediction(df_scaled):
    rf_pred  = rf_model.predict(df_scaled)[0]
    xgb_pred = xgb_model.predict(df_scaled)[0]
    return rf_pred, xgb_pred

# ---------------- BEHAVIOR ---------------- #
def behavioral_score(f):
    score = 0
    if f["process_count"] > 50: score += 1
    if f["process_density"] > 0.5: score += 1
    if f["handles_total"] > 100: score += 1
    if f["handle_density"] > 10: score += 1
    if f["mal_injections"] > 10: score += 2
    if f["dll_count"] > 100: score += 1
    if f["dlls_per_process"] > 5: score += 1
    if f["service_count"] > 50: score += 1
    if f["mal_commit_charge"] > 20: score += 1
    if f["total_activity"] > 50000: score += 1
    return score

# ---------------- MAIN ---------------- #
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    features = None
    importance = None

    rf_pred = None
    xgb_pred = None
    iso_pred = None
    b_score = None
    votes = None

    if request.method == "POST":
        file = request.files["file"]
        path = os.path.join("uploads", file.filename)
        file.save(path)

        event_count = load_sysmon(path)
        features = extract_features(event_count)

        total_activity = features["total_activity"]
        process_count = features["process_count"]
        total_feature_sum = sum(v for v in features.values() if isinstance(v, (int, float)))

        # 🔥 SAFETY CHECK
        if process_count == 0:
            result = "INVALID LOG"

        elif total_feature_sum <= 5:
            result = "BENIGN"

        elif total_activity < 30 and process_count < 5:
            result = "BENIGN"

        else:
            b_score = behavioral_score(features)
            df_scaled = build_scaled_df(features)

            rf_pred, xgb_pred = ml_prediction(df_scaled)
            iso_pred = iso_model.predict(df_scaled)[0]

            votes = 0
            if b_score >= 4: votes += 1
            if rf_pred == 1: votes += 1
            if xgb_pred == 1: votes += 1
            if iso_pred == -1: votes += 1

            if votes >= 3:
                result = "RANSOMWARE"
            elif votes == 2:
                result = "RANSOMWARE" if total_activity > 30 else "BENIGN"
            else:
                result = "BENIGN"

        scan_stats["files_scanned"] += 1
        if result == "RANSOMWARE":
            scan_stats["threats_detected"] += 1
        else:
            scan_stats["safe_files"] += 1

        # Behavior-based importance (general)
        importance = {}

        for key, value in features.items():
            if isinstance(value, (int, float)):
                importance[key] = value

    # sort descending
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

    return render_template(
        "index.html",
        result=result,
        features=features,
        importance=importance,
        files_scanned=scan_stats["files_scanned"],
        safe_files=scan_stats["safe_files"],
        threats_detected=scan_stats["threats_detected"],
        rf_pred=rf_pred,
        xgb_pred=xgb_pred,
        iso_pred=iso_pred,
        b_score=b_score,
        votes=votes
    )

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    app.run(debug=True)