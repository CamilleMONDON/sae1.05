import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
import csv
import webbrowser
from collections import Counter

csv_path = None
md_path = None
html_path = None
# UTILITAIRES
def extract_val(line, keyword):
    if keyword not in line:
        return ""
    try:
        parts = line.split(keyword)
        if len(parts) > 1:
            value = parts[1].strip().split()[0].strip(',').strip(':').strip(']')
            return value
    except:
        pass
    return ""
def separer_ip_port(adresse_complete):
    if "." not in adresse_complete:
        return adresse_complete, ""
    parts = adresse_complete.rsplit('.', 1)
    if parts[1].isdigit() or parts[1] in ["http", "https", "domain", "ssh", "ftp"]:
        return parts[0], parts[1]
    return adresse_complete, ""
# DÉTECTION DES MENACES
def detecter_attaques(data_rows):
    scans_ports = {}
    packet_count_scan = {}
    syn_counts = {}
    alertes_web = []
    LIMIT_SYN_HIGH = 50
    LIMIT_SYN_MID = LIMIT_SYN_HIGH / 2
    LIMIT_SCAN_PORTS = 10
    LIMIT_SCAN_MAX = LIMIT_SCAN_PORTS + 30
    for row in data_rows:
        ip_src = row["Source_IP"]
        port_dst = row["Dest_Port"]
        flags = row["Flags"]
        if ip_src not in scans_ports:
            scans_ports[ip_src] = set()
            packet_count_scan[ip_src] = 0
        if port_dst:
            scans_ports[ip_src].add(port_dst)
            packet_count_scan[ip_src] += 1
        if "S" in flags:
            syn_counts[ip_src] = syn_counts.get(ip_src, 0) + 1
    for ip, count in syn_counts.items():
        if count >= LIMIT_SYN_MID:
            niveau = "HIGH" if count >= LIMIT_SYN_HIGH else "MID"
            alertes_web.append({
                "ip": ip,
                "type": "SYN Flood",
                "nb_packets": count,
                "details": f"Attaque par inondation ({count} paquets SYN)",
                "niveau": niveau
            })
    for ip, ports in scans_ports.items():
        if len(ports) > LIMIT_SCAN_PORTS:
            total_pkts = packet_count_scan[ip]
            niveau = "HIGH" if len(ports) >= LIMIT_SCAN_MAX else "MID"
            alertes_web.append({
                "ip": ip,
                "type": "Scan de Ports",
                "nb_packets": total_pkts,
                "details": f"Scan sur {len(ports)} ports ({total_pkts} paquets)",
                "niveau": niveau
            })
    return alertes_web

#  PARSING TCPDUMP
def parse_tcpdump_flexible(input_path, output_csv):
    headers = ["Horodatage", "Source_IP", "Source_Port", "Dest_IP", "Dest_Port",
               "Flags", "Sequence", "Acknowledgment", "Window", "Length"]
    data_rows = []
    if not os.path.exists(input_path):
        messagebox.showerror("Erreur", f"{input_path} introuvable")
        return [], []
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or not line[0].isdigit():
                continue
            parts = line.split()
            if len(parts) < 5 or parts[1] != "IP":
                continue
            src_raw = parts[2]
            dst_raw = parts[4].rstrip(':')
            src_ip, src_port = separer_ip_port(src_raw)
            dst_ip, dst_port = separer_ip_port(dst_raw)
            flags = ""
            if "[" in line and "]" in line:
                flags = line[line.find("[")+1 : line.find("]")]
            data_rows.append({
                "Horodatage": parts[0],
                "Source_IP": src_ip,
                "Source_Port": src_port,
                "Dest_IP": dst_ip,
                "Dest_Port": dst_port,
                "Flags": flags,
                "Sequence": extract_val(line, "seq"),
                "Acknowledgment": extract_val(line, "ack"),
                "Window": extract_val(line, "win"),
                "Length": extract_val(line, "length")
            })
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers, delimiter=';')
        writer.writeheader()
        writer.writerows(data_rows)
    alertes = detecter_attaques(data_rows)
    return data_rows, alertes

# RAPPORT HTML
def generer_rapport_html(data_rows, alertes, dossier_sortie, nom_fichier):
    import webbrowser
    from collections import Counter
    import os

    html_path = os.path.join(dossier_sortie, f"{nom_fichier}_rapport.html")
    top_sources = Counter([row["Source_IP"] for row in data_rows]).most_common(5)
    top_dest = Counter([row["Dest_IP"] for row in data_rows]).most_common(5)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport SAE 1.05</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {{
  --bg: #ffffff; --card: #ffffff; --text: #000000;
  --accent: #f97316; --secondary: #0ea5e9; --border: #000000;
  --header-bg: #f97316;
}}
[data-theme="dark"] {{
  --bg: #000000; --card: #1c1917; --text: #ffffff; --border: #ffffff;
}}
body {{
  margin:0; font-family: "Comic Sans MS", cursive;
  background:var(--bg); color:var(--text); transition: 0.3s;
}}
header {{
  display:flex; justify-content:space-between; align-items:center;
  padding:15px 30px; background: var(--header-bg); color: white;
  border-bottom: 3px solid black;
}}
.btn-group {{ display: flex; gap: 10px; }}
.btn {{
  background: white; border: 2px solid #000; padding: 8px 15px;
  border-radius: 10px; cursor: pointer; font-family: inherit; font-weight: bold;
}}
.container {{ max-width:1100px; margin:auto; padding:20px; display:grid; gap:25px; }}
.card {{
  background:var(--card); padding:20px; border-radius:15px;
  border: 3px solid var(--text); box-shadow: 8px 8px 0px rgba(0,0,0,0.1);
}}
h2 {{ color: var(--secondary); text-decoration: underline var(--accent); }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ padding:10px; border: 2px solid var(--text); text-align:left; }}
th {{ background: var(--secondary); color: white; }}
.badge {{ padding:4px 10px; border-radius:5px; font-weight:bold; color:white; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(450px,1fr)); gap:25px; }}
footer {{ text-align: center; padding: 20px; opacity: 0.7; font-size: 0.9em; }}
</style>
</head>
<body data-theme="light">

<header>
  <h1 class="lang" data-fr="📡 Analyseur Réseau - SAE 1.05" data-en="📡 Network Analyzer - SAE 1.05">📡 Analyseur Réseau - SAE 1.05</h1>
  <div class="btn-group">
    <button class="btn" id="btnLang" onclick="toggleLang()">English</button>
    <button class="btn lang" id="btnTheme" onclick="toggleTheme()" data-fr="🌓 Mode" data-en="🌓 Mode">🌓 Mode</button>
  </div>
</header>

<div class="container">
  <div class="card">
    <h2 class="lang" data-fr="🚨 Menaces Détectées" data-en="🚨 Detected Threats">🚨 Menaces Détectées</h2>
    <table>
      <thead>
        <tr>
          <th class="lang" data-fr="IP Source" data-en="Source IP">IP Source</th>
          <th class="lang" data-fr="Type" data-en="Type">Type</th>
          <th class="lang" data-fr="Paquets" data-en="Packets">Paquets</th>
          <th class="lang" data-fr="Détails" data-en="Details">Détails</th>
          <th class="lang" data-fr="Niveau" data-en="Level">Niveau</th>
        </tr>
      </thead>
      <tbody>
""")
        if alertes:
            for a in alertes:
                color = "#dc2626" if "ÉLEVÉ" in a['niveau'] else "#f97316"
                # Traduction dynamique des types et détails
                type_en = a['type'].replace('Scan de ports', 'Port Scan')
                det_en = a['details'].replace('Volume', 'Volume').replace('paquets', 'packets').replace('Tentative', 'Attempt').replace('ports différents', 'different ports')
                niv_en = a['niveau'].replace('ÉLEVÉ', 'HIGH').replace('MOYEN', 'MEDIUM')

                f.write(f"""
        <tr>
          <td>{a['ip']}</td>
          <td class="lang" data-fr="{a['type']}" data-en="{type_en}">{a['type']}</td>
          <td>{a['nb_packets']}</td>
          <td class="lang" data-fr="{a['details']}" data-en="{det_en}">{a['details']}</td>
          <td><span class="badge lang" style="background:{color}" data-fr="{a['niveau']}" data-en="{niv_en}">{a['niveau']}</span></td>
        </tr>""")
        else:
            f.write('<tr><td colspan="5" style="text-align:center;" class="lang" data-fr="✅ Aucune activité suspecte" data-en="✅ No suspicious activity">✅ Aucune activité suspecte</td></tr>')

        f.write(f"""
      </tbody>
    </table>
  </div>

  <div class="grid">
    <div class="card"><h2 class="lang" id="titleSrc" data-fr="Top 5 Sources" data-en="Top 5 Sources">Top 5 Sources</h2><canvas id="srcChart"></canvas></div>
    <div class="card"><h2 class="lang" id="titleDst" data-fr="Top 5 Destinations" data-en="Top 5 Destinations">Top 5 Destinations</h2><canvas id="dstChart"></canvas></div>
  </div>
</div>

<footer class="lang" data-fr="Généré pour le service informatique - Roanne" data-en="Generated for IT Department - Roanne">
  Généré pour le service informatique - Roanne
</footer>

<script>
let currentLang = 'fr';

function toggleTheme() {{
    document.body.dataset.theme = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
}}

function toggleLang() {{
    currentLang = currentLang === 'fr' ? 'en' : 'fr';
    document.getElementById('btnLang').innerText = currentLang === 'fr' ? 'English' : 'Français';

    // Traduction de tous les éléments avec la classe .lang
    document.querySelectorAll('.lang').forEach(el => {{
        el.innerText = el.getAttribute('data-' + currentLang);
    }});
}}

const commonOptions = {{
    responsive: true,
    plugins: {{
        legend: {{
            position: 'bottom',
            labels: {{ font: {{ family: 'Comic Sans MS', size: 12 }} }}
        }}
    }}
}};

new Chart(document.getElementById('srcChart'), {{
  type: 'pie',
  data: {{
    labels: {[ip for ip, _ in top_sources]},
    datasets: [{{ data: {[c for _, c in top_sources]}, backgroundColor: ['#f97316', '#0ea5e9', '#fb923c', '#38bdf8', '#fdba74'], borderColor: '#000', borderWidth: 2 }}]
  }},
  options: commonOptions
}});

new Chart(document.getElementById('dstChart'), {{
  type: 'pie',
  data: {{
    labels: {[ip for ip, _ in top_dest]},
    datasets: [{{ data: {[c for _, c in top_dest]}, backgroundColor: ['#f97316', '#0ea5e9', '#fb923c', '#38bdf8', '#fdba74'], borderColor: '#000', borderWidth: 2 }}]
  }},
  options: commonOptions
}});
</script>
</body>
</html>
""")
    webbrowser.open(f"file://{html_path}")

# TRAITEMENT FICHIER
def traiter_fichier(chemin, dossier_sortie):
    global csv_path, md_path

    nom_fichier = os.path.splitext(os.path.basename(chemin))[0]
    csv_path = os.path.join(dossier_sortie, f"{nom_fichier}_output.csv")
    md_path = os.path.join(dossier_sortie, f"{nom_fichier}_report.md")

    data_rows, alertes = parse_tcpdump_flexible(chemin, csv_path)

    if not data_rows:
        messagebox.showinfo("Info", "Aucune donnée exploitable")
        return None

    # Markdown
    with open(md_path, "w", encoding="utf-8") as md:
        md.write("# Rapport trafic réseau\n\n")
        if alertes:
            md.write("## Menaces détectées\n\n")
            md.write("| IP source | Type | Nb Paquets | Détails | Niveau |\n|---|---|---|---|---|\n")
            for a in alertes:
                md.write(f"| {a['ip']} | {a['type']} | {a['nb_packets']} | {a['details']} | {a['niveau']} |\n")
        else:
            md.write("Aucune menace détectée\n")

    generer_rapport_html(data_rows, alertes, dossier_sortie, nom_fichier)

    if alertes:
        messagebox.showwarning("Menaces détectées", f"{len(alertes)} menaces détectées")

    return csv_path

# TKINTER
def choisir_fichier():
    chemin = filedialog.askopenfilename(filetypes=[("Fichiers texte", "*.txt"), ("Tous fichiers", "*.*")])
    if chemin:
        dossier_sortie = filedialog.askdirectory()
        if dossier_sortie:
            if traiter_fichier(chemin, dossier_sortie):
                btn_csv.config(state="normal")
                btn_md.config(state="normal")
                btn_html.config(state="normal")

def ouvrir_fichier(path):
    if path and os.path.exists(path):
        os.startfile(path) if os.name=="nt" else subprocess.call(["xdg-open", path])

fenetre = tk.Tk()
fenetre.title("Analyseur trafic réseau")

tk.Button(fenetre, text="Choisir fichier TXT", command=choisir_fichier).pack(pady=10)
btn_csv = tk.Button(fenetre, text="Ouvrir CSV", command=lambda: ouvrir_fichier(csv_path), state="disabled")
btn_csv.pack()
btn_md = tk.Button(fenetre, text="Ouvrir Markdown", command=lambda: ouvrir_fichier(md_path), state="disabled")
btn_md.pack()
btn_html = tk.Button(fenetre, text="Ouvrir HTML", command=lambda: ouvrir_fichier(html_path), state="disabled")
btn_html.pack()
tk.Button(fenetre, text="Quitter", command=fenetre.destroy).pack(pady=10)

fenetre.mainloop()