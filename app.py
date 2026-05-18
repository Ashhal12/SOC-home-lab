from flask import Flask, render_template_string
import subprocess
import json
import re

app = Flask(__name__)

def get_suricata_alerts():
    alerts = []
    try:
        with open('/var/log/suricata/fast.log', 'r') as f:
            lines = f.readlines()[-50:]
            for line in lines:
                if '[**]' in line:
                    alerts.append(line.strip())
    except:
        pass
    return alerts

def get_wazuh_alerts():
    alerts = []
    try:
        result = subprocess.run(['sudo', 'tail', '-n', '100', '/var/ossec/logs/alerts/alerts.log'], 
                              capture_output=True, text=True)
        lines = result.stdout.split('\n')
        current_alert = []
        for line in lines:
            if '** Alert' in line:
                if current_alert:
                    alerts.append(' | '.join(current_alert[:3]))
                current_alert = [line.strip()]
            elif line.strip() and current_alert:
                current_alert.append(line.strip())
        if len(alerts) > 20:
            alerts = alerts[-20:]
    except:
        pass
    return alerts

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SOC Dashboard - Ashhal</title>
    <meta http-equiv="refresh" content="10">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0e1a; color: #00ff88; font-family: monospace; }
        .header { background: #0d1b2a; padding: 20px; text-align: center; border-bottom: 2px solid #00ff88; }
        .header h1 { font-size: 28px; color: #00ff88; }
        .header p { color: #888; margin-top: 5px; }
        .stats { display: flex; justify-content: center; gap: 30px; padding: 20px; flex-wrap: wrap; }
        .stat-box { background: #0d1b2a; border: 1px solid #00ff88; border-radius: 8px; padding: 20px; text-align: center; min-width: 150px; }
        .stat-box h2 { font-size: 36px; color: #ff4444; }
        .stat-box.green h2 { color: #00ff88; }
        .stat-box.yellow h2 { color: #ffaa00; }
        .stat-box p { color: #888; margin-top: 5px; }
        .section { margin: 20px; }
        .section h3 { color: #00aaff; border-bottom: 1px solid #00aaff; padding-bottom: 10px; margin-bottom: 15px; font-size: 18px; }
        .alert-box { background: #0d1b2a; border-left: 4px solid #ff4444; padding: 10px 15px; margin-bottom: 8px; border-radius: 4px; font-size: 13px; word-break: break-all; }
        .alert-box.wazuh { border-left-color: #00aaff; }
        .network-info { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px; }
        .host-card { background: #0d1b2a; border: 1px solid #333; border-radius: 8px; padding: 15px; flex: 1; min-width: 200px; }
        .host-card h4 { color: #00ff88; margin-bottom: 10px; }
        .host-card p { color: #aaa; font-size: 13px; margin: 5px 0; }
        .status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #00ff88; margin-right: 8px; }
        .footer { text-align: center; padding: 20px; color: #444; border-top: 1px solid #222; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SOC Home Lab Dashboard</h1>
        <p>Real-time Security Monitoring | Auto-refresh every 10 seconds</p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <h2>{{ suricata_count }}</h2>
            <p>Suricata Alerts</p>
        </div>
        <div class="stat-box yellow">
            <h2>{{ wazuh_count }}</h2>
            <p>Wazuh Events</p>
        </div>
        <div class="stat-box green">
            <h2>3</h2>
            <p>Active VMs</p>
        </div>
        <div class="stat-box">
            <h2>ON</h2>
            <p>IDS Status</p>
        </div>
    </div>

    <div class="network-info">
        <div class="host-card">
            <h4><span class="status-dot"></span>Ubuntu SIEM</h4>
            <p>IP: 192.168.74.139</p>
            <p>Role: Monitor/SIEM</p>
            <p>Tools: Wazuh + Suricata</p>
        </div>
        <div class="host-card">
            <h4><span class="status-dot"></span>Windows Victim</h4>
            <p>IP: 192.168.74.140</p>
            <p>Role: Victim Machine</p>
            <p>Tools: Wazuh Agent</p>
        </div>
        <div class="host-card">
            <h4><span class="status-dot" style="background:#ff4444"></span>Kali Attacker</h4>
            <p>IP: 192.168.74.129</p>
            <p>Role: Attacker</p>
            <p>Tools: Nmap, Metasploit</p>
        </div>
    </div>

    <div class="section">
        <h3> Suricata IDS Alerts (Last 50)</h3>
        {% for alert in suricata_alerts %}
        <div class="alert-box">{{ alert }}</div>
        {% endfor %}
        {% if not suricata_alerts %}
        <div class="alert-box">No alerts yet — run an attack from Kali!</div>
        {% endif %}
    </div>

    <div class="section">
        <h3>Wazuh SIEM Events (Last 20)</h3>
        {% for alert in wazuh_alerts %}
        <div class="alert-box wazuh">{{ alert }}</div>
        {% endfor %}
        {% if not wazuh_alerts %}
        <div class="alert-box wazuh">No events yet</div>
        {% endif %}
    </div>

    <div class="footer">
        SOC Home Lab | Built by Ashhal | Suricata + Wazuh + Flask
    </div>
</body>
</html>
'''

@app.route('/')
def dashboard():
    suricata_alerts = get_suricata_alerts()
    wazuh_alerts = get_wazuh_alerts()
    return render_template_string(HTML_TEMPLATE,
        suricata_alerts=suricata_alerts,
        wazuh_alerts=wazuh_alerts,
        suricata_count=len(suricata_alerts),
        wazuh_count=len(wazuh_alerts)
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
