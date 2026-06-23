import os, re, subprocess, requests, urllib3, json, datetime
urllib3.disable_warnings()

api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    print("❌ ERROR: GROQ_API_KEY environment variable is missing!")
    exit(1)

LOG_FILE  = "cyber_soar.log"
MODEL_ID  = "openai/gpt-oss-20b"

def log_incident(data):
    data["timestamp"] = datetime.datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def check_model_active(model_id, headers):
    try:
        res = requests.get("https://api.groq.com/openai/v1/models", headers=headers).json()
        active_ids = [m["id"] for m in res.get("data", [])]
        if model_id not in active_ids:
            print(f"⚠️  Model '{model_id}' not found on Groq!")
            print(f"   Active models: {active_ids}")
            return False
        print(f"✅ Model '{model_id}' confirmed active.")
        return True
    except Exception as e:
        print(f"⚠️  Could not verify model: {e}")
        return True

def extract_json_safe(text):
    fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if fenced:
        return fenced.group(1).strip()
    brace_match = re.search(r"\{[\s\S]*\}", text)
    if brace_match:
        return brace_match.group(0).strip()
    return text.strip()

groq_headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

check_model_active(MODEL_ID, groq_headers)

splunk_url  = "https://192.168.56.1:8089/services/search/jobs?output_mode=json"
splunk_data = {
    "search": 'search index=suricata alert.signature="*SYN*" src_ip="192.168.56.101" | stats count by src_ip, alert.signature | table src_ip, alert.signature, count',
    "exec_mode":     "oneshot",
    "earliest_time": "-24h",
    "latest_time":   "now"
}
res = requests.post(splunk_url, auth=("tspoojasri", "ptssrisplunk"), data=splunk_data, verify=False).json()

if res.get("results"):
    alert     = res["results"][0]
    src_ip    = alert["src_ip"]
    signature = alert["alert.signature"]
    count     = alert.get("count", "1")
    print(f"\n🚨 [SIEM INGEST] Alert Triggered: {signature} from {src_ip} | Event Count: {count}")
    prompt = (
         f"Analyze alert: {signature} from IP {src_ip}. "
         f"This signature fired {count} times in 24 hours. "
         f"Respond ONLY with a valid raw JSON object. No markdown. "
         f"Keys: 'attack_type', 'severity' (int 1-10), 'confidence' (int 1-100), "
         f"'impact_scope', 'mitre_id', 'recommended_action', 'justification'."
    )
    payload = {
        "model": MODEL_ID,
        "messages": [
            {"role": "system", "content": "You are a threat intelligence analyst API. Output ONLY a raw JSON object. No markdown, no explanation, no preamble. Ever."},
            {"role": "user",   "content": prompt}
        ],
        "temperature": 0.1
    }

    ai_res  = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=groq_headers, json=payload).json()
    content = "{}"
    if "choices" in ai_res:
        raw_content = ai_res["choices"][0]["message"]["content"].strip()
        content     = extract_json_safe(raw_content)
    else:
        print(f"⚠️  Groq API Error: {json.dumps(ai_res, indent=2)}")

    try:
        decision     = json.loads(content)
        severity     = max(0, min(10,  int(decision.get("severity",   0))))
        confidence   = max(0, min(100, int(decision.get("confidence", 0))))
        attack_type  = decision.get("attack_type",        "Unknown")
        impact_scope = decision.get("impact_scope",       "Unknown")
        mitre_id     = decision.get("mitre_id",           "N/A")
        rec_action   = decision.get("recommended_action", "monitor")
        justification= decision.get("justification",      "No analysis provided.")
    except (json.JSONDecodeError, ValueError):
        print("⚠️  Malformed LLM response. Entering fail-safe defaults.")
        severity, confidence      = 0, 0
        attack_type, impact_scope = "Error", "Unknown"
        mitre_id, rec_action      = "N/A", "monitor"
        justification             = "Failed to parse LLM response."

    print(f"\n🧠 [SOAR THREAT INTELLIGENCE ENRICHMENT]")
    print(f"   🔹 Attack Type     : {attack_type}")
    print(f"   🔹 MITRE ATT&CK    : {mitre_id}")
    print(f"   🔹 Impact Scope    : {impact_scope}")
    print(f"   🔹 AI Confidence   : {confidence}%")
    print(f"   🔹 Triaged Severity: {severity}/10")
    print(f"   🔹 Rec. Action     : {rec_action[:60]}{'...' if len(rec_action) > 60 else ''}")
    print(f"   🔹 Analyst Note    : {justification[:80]}{'...' if len(justification) > 80 else ''}\n")

    if severity >= 7 and confidence >= 80 and "block" in rec_action.lower():
        print(f"⚡ [ORCHESTRATION ENGINE] Risk thresholds met. Isolating {src_ip}...")
        subprocess.run(f"sudo iptables -I INPUT -s {src_ip} -j DROP", shell=True)
        subprocess.run("sudo systemctl enable --now atd", shell=True, capture_output=True)
        subprocess.run(f"echo 'sudo iptables -D INPUT -s {src_ip} -j DROP' | at now + 10 minutes", shell=True)
        print(f"🛡️  Active Defense Rule Engaged. Auto-cleanup in 10 min.")
        action_taken = "IP_BLOCKED_TEMPORARY"
    else:
        print(f"ℹ️  [ORCHESTRATION ENGINE] Below mitigation threshold. Monitoring only.")
        action_taken = "NO_ACTION_MONITOR_ONLY"

    log_incident({
        "source_ip": src_ip, "signature": signature, "attack_type": attack_type,
        "mitre_id": mitre_id, "severity": severity, "confidence": confidence,
        "recommended_action": rec_action, "action_executed": action_taken
    })
    print(f"📁 Incident logged to: {LOG_FILE}")

else:
    print("🟢 No new matching alerts found in the last 24 hours.")
