package main

import (
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"interactive-scraper/internal/analysis"
	"interactive-scraper/internal/models"
	"interactive-scraper/internal/repository"
	"gopkg.in/yaml.v2"
)

var isAuthenticated = false

func main() {
	repository.InitDB()
	
	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/detail", detailHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/settings/add", addRuleHandler)
	http.HandleFunc("/settings/delete", deleteRuleHandler)
	
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/clear", clearHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("---------------------------------------------------")
	fmt.Println(" 🛡️   SOC DASHBOARD SYSTEM ONLINE")
	fmt.Println("      http://localhost:8080")
	fmt.Println("---------------------------------------------------")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ---------------------- LOGIN ----------------------
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if r.FormValue("username") == "admin" && r.FormValue("password") == "password" {
			isAuthenticated = true
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}
	w.Write([]byte(`<!DOCTYPE html><html><head><title>SECURE LOGIN</title><link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet"><style>body{background:#000;color:#0f0;font-family:'Share Tech Mono';display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.box{border:1px solid #0f0;padding:40px;width:300px;text-align:center;background:#050505;box-shadow:0 0 20px rgba(0,255,0,0.2)}input{background:#111;border:1px solid #0f0;color:white;padding:10px;width:90%;margin:10px 0}button{background:#0f0;color:black;border:none;padding:10px;width:100%;cursor:pointer;font-weight:bold;margin-top:10px}</style></head><body><div class="box"><h2>/// SOC_ACCESS</h2><form method="POST"><input type="text" name="username" placeholder="OPERATOR"><input type="password" name="password" placeholder="TOKEN"><button type="submit">INITIALIZE</button></form></div></body></html>`))
}

// ---------------------- SCAN ----------------------
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated { http.Redirect(w, r, "/", http.StatusSeeOther); return }

	repository.SetScanProgress(1)

	go func() {
		logFile, _ := os.OpenFile("scan_report.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer logFile.Close()
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger := log.New(multiWriter, "", 0)

		data, _ := ioutil.ReadFile("targets.yaml")
		var config models.TargetConfig
		yaml.Unmarshal(data, &config)
		rules := repository.GetRules()
		total := len(config.Targets)

		logger.Println("\n--- GERÇEK TOR TARAMASI BAŞLATILDI ---")

		for i, target := range config.Targets {
			p := (i + 1) * 100 / total
			repository.SetScanProgress(p)
			
			logger.Printf("[SCAN %d%%] Bağlanıyor: %s (%s)...", p, target.Name, target.URL)

			title, content := analysis.AnalyzeContent(target.URL)
			
			ip, country, port := analysis.GenerateMetadata()

			fullContent := strings.ToLower(title + "\n" + content)
			highestRiskScore := 0 
			finalRiskLevel := "Düşük"
			
			var detectedThreats []string
			
			statusText := "CLEAN"
			if strings.Contains(title, "HATA") {
				statusText = "UNREACHABLE"
				finalRiskLevel = "Bilinmiyor"
				detectedThreats = append(detectedThreats, "Siteye Erişilemedi")
			} else {
				statusText = "ONLINE"
				for _, rule := range rules {
					pattern := fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(rule.Keyword))
					re := regexp.MustCompile(pattern)
					if re.MatchString(fullContent) {
						currentScore := 0
						switch rule.RiskLevel {
						case "Yüksek": currentScore = 3
						case "Orta": currentScore = 2
						default: currentScore = 1
						}
						if currentScore > highestRiskScore {
							highestRiskScore = currentScore
							finalRiskLevel = rule.RiskLevel
						}
						threatLog := fmt.Sprintf("[%s] Bulundu: %s", rule.RiskLevel, rule.Keyword)
						detectedThreats = append(detectedThreats, threatLog)
					}
				}
			}

			if len(detectedThreats) > 0 && statusText == "ONLINE" {
				statusText = "INFECTED"
			}

			evidenceText := strings.Join(detectedThreats, " || ")
			if len(detectedThreats) == 0 { evidenceText = "Tehdit yok veya site kapalı." }

			repository.SaveData(models.ScrapedData{
				SourceName:       target.Name,
				SourceURL:        target.URL,
				Title:            title,
				RawContent:       content,
				CriticalityScore: highestRiskScore * 3,
				CriticalityLevel: finalRiskLevel,
				ScanDate:         time.Now(),
				Status:           statusText,
				MatchedKeyword:   fmt.Sprintf("%d Olay", len(detectedThreats)),
				RiskEvidence:     evidenceText,
				SourceIP:         ip,
				SourceCountry:    country,
				SourcePort:       port,
			})
			
			logger.Printf("   -> Durum: %s | Başlık: %s\n", statusText, title)
		}
		
		repository.SetScanProgress(0)
		logger.Println("--- TARAMA TAMAMLANDI ---")
	}()

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// ---------------------- CLEAR HANDLER ----------------------
func clearHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	repository.ClearAllData()
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// ---------------------- DASHBOARD ----------------------
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated { http.Redirect(w, r, "/", http.StatusSeeOther); return }

	data := repository.GetAllData()
	t, h, m, l := repository.GetStats()
	prog := repository.GetScanProgress()

	catStats := map[string]int{
		"SQL_Inj": 0, "Carding": 0, "Markets": 0, "PII_Leak": 0,
		"Ransom":  0, "Phishing": 0, "Botnet":  0, "Malware": 0,
		"Exploit": 0, "Crypto":   0, "Counter": 0, "Other":   0,
	}

	for _, d := range data {
		txt := strings.ToLower(d.Title + d.RiskEvidence + d.SourceName)
		
		if strings.Contains(txt, "sql") || strings.Contains(txt, "injection") { catStats["SQL_Inj"]++ } else 
		if strings.Contains(txt, "card") || strings.Contains(txt, "cc") || strings.Contains(txt, "cvv") { catStats["Carding"]++ } else 
		if strings.Contains(txt, "market") || strings.Contains(txt, "shop") || strings.Contains(txt, "store") { catStats["Markets"]++ } else
		if strings.Contains(txt, "mernis") || strings.Contains(txt, "identity") || strings.Contains(txt, "tcno") { catStats["PII_Leak"]++ } else
		if strings.Contains(txt, "ransom") || strings.Contains(txt, "encrypt") || strings.Contains(txt, "lock") { catStats["Ransom"]++ } else
		if strings.Contains(txt, "phish") || strings.Contains(txt, "fake") || strings.Contains(txt, "spoof") { catStats["Phishing"]++ } else
		if strings.Contains(txt, "bot") || strings.Contains(txt, "c2") || strings.Contains(txt, "ddos") { catStats["Botnet"]++ } else
		if strings.Contains(txt, "stealer") || strings.Contains(txt, "trojan") || strings.Contains(txt, "malware") { catStats["Malware"]++ } else
		if strings.Contains(txt, "exploit") || strings.Contains(txt, "cve") || strings.Contains(txt, "zero-day") { catStats["Exploit"]++ } else
		if strings.Contains(txt, "crypto") || strings.Contains(txt, "wallet") || strings.Contains(txt, "seed") { catStats["Crypto"]++ } else
		if strings.Contains(txt, "counterfeit") || strings.Contains(txt, "fake money") || strings.Contains(txt, "passport") { catStats["Counter"]++ } else
		{ catStats["Other"]++ }
	}

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>SOC COMMAND CENTER</title>
		<link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
		<script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
		<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
		<style>
			:root { --neon: #00f3ff; --alert: #ff003c; --warn: #ffcc00; --safe: #00ff00; --bg: #020202; --panel: #0a0a0a; }
			body { background-color: var(--bg); color: #ccc; font-family: 'Share Tech Mono', monospace; margin: 0; padding: 20px; }
			.header { display: flex; justify-content: space-between; border-bottom: 2px solid var(--neon); padding-bottom: 10px; margin-bottom: 20px; align-items: center; }
			.logo { font-size: 28px; color: var(--neon); text-shadow: 0 0 10px var(--neon); letter-spacing: 2px; }
			.stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
			.stat-box { background: var(--panel); border: 1px solid #333; padding: 20px; position: relative; overflow: hidden; }
			.stat-box::before { content:''; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--neon); }
			.stat-box.danger::before { background: var(--alert); }
			.stat-val { font-size: 36px; color: white; font-weight: bold; }
			.stat-label { font-size: 12px; color: #888; text-transform: uppercase; }
			.mid-grid { display: grid; grid-template-columns: 1.5fr 1fr; gap: 20px; margin-bottom: 20px; height: 400px; }
			.card { background: var(--panel); border: 1px solid #333; padding: 15px; display: flex; flex-direction: column; }
			.card-title { color: var(--neon); font-size: 14px; border-bottom: 1px dashed #444; padding-bottom: 10px; margin-bottom: 15px; text-transform: uppercase; }
			#map { flex-grow: 1; width: 100%; background: #111; }
			.table-container { overflow-x: auto; }
			table { width: 100%; border-collapse: collapse; font-size: 13px; }
			th { text-align: left; color: var(--neon); background: #111; padding: 12px; border-bottom: 2px solid #333; }
			td { padding: 10px 12px; border-bottom: 1px solid #222; color: #ddd; }
			.btn { border: 1px solid var(--neon); color: var(--neon); padding: 8px 20px; text-decoration: none; font-size: 12px; transition: 0.3s; cursor: pointer; }
			.btn:hover { background: var(--neon); color: black; }
			.badge { padding: 4px 8px; font-size: 10px; border-radius: 2px; font-weight: bold; text-transform: uppercase; }
			.risk-Yüksek { background: rgba(255, 0, 60, 0.2); color: var(--alert); border: 1px solid var(--alert); }
		</style>
	</head>
	<body>
		<div class="header">
			<div class="logo">/// CTI_SOC_DASHBOARD</div>
			<div>
				<a href="/scan" class="btn">SCAN NETWORK</a>
				<a href="/clear" class="btn" style="border-color:var(--alert); color:var(--alert);">PURGE DB</a>
				<a href="/settings" class="btn">CONFIG</a>
				<a href="/logout" class="btn">LOGOUT</a>
			</div>
		</div>

		{{if gt .Progress 0}}
		<div style="margin-bottom: 20px;">
			<div style="width: 100%; background: #111; border: 1px solid var(--neon); height: 35px; position: relative;">
				<div style="width: {{.Progress}}%; background: var(--neon); height: 100%; transition: width 0.5s ease; box-shadow: 0 0 20px var(--neon);"></div>
				<div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
					SYSTEM SCANNING... %{{.Progress}}
				</div>
			</div>
			<script>setTimeout(function(){ location.reload(); }, 1000);</script>
		</div>
		{{end}}

		<div class="stats-row">
			<div class="stat-box"><div class="stat-val">{{.Total}}</div><div class="stat-label">Total Logs</div></div>
			<div class="stat-box danger"><div class="stat-val">{{.High}}</div><div class="stat-label">High Risk</div></div>
			<div class="stat-box"><div class="stat-val">{{.Med}}</div><div class="stat-label">Med Risk</div></div>
			<div class="stat-box"><div class="stat-val">{{.Low}}</div><div class="stat-label">Info</div></div>
		</div>

		<div class="mid-grid">
			<div class="card">
				<div class="card-title">Global Threat Origin</div>
				<div id="map"></div>
			</div>
			<div class="card">
				<div class="card-title">Threat Categorization (12 Vectors)</div>
				<div style="position: relative; height: 100%; width:100%;">
					<canvas id="catChart"></canvas>
				</div>
			</div>
		</div>

		<div class="card">
			<div class="card-title">Recent Intelligence Feed</div>
			<div class="table-container">
				<table>
					<thead>
						<tr>
							<th>#ID</th><th>SOURCE</th><th>TITLE</th><th>TIME</th><th>SEVERITY</th><th>ACTION</th>
						</tr>
					</thead>
					<tbody>
						{{range .Data}}
						<tr>
							<td>{{.ID}}</td>
							<td><span style="color:white; background:#222; padding:3px 6px;">{{.SourceName}}</span></td>
							<td style="color:#aaa;">{{.Title}}</td>
							<td style="color:#666;">{{.ScanDate.Format "15:04:05"}}</td>
							<td><span class="badge risk-{{.CriticalityLevel}}">{{.CriticalityLevel}}</span></td>
							<td><a href="/detail?id={{.ID}}" class="btn" style="padding:4px 10px; font-size:10px;">INSPECT</a></td>
						</tr>
						{{end}}
					</tbody>
				</table>
			</div>
		</div>

		<script>
			const ctx = document.getElementById('catChart').getContext('2d');
			new Chart(ctx, { 
				type: 'radar', 
				data: { 
					labels: ['SQL Injection', 'Carding', 'Markets', 'PII Leak', 'Ransomware', 'Phishing', 'Botnet', 'Malware', 'Exploits', 'Crypto', 'Counterfeit', 'Other'], 
					datasets: [{ 
						label: 'Threat Count',
						data: [{{.C.SQL_Inj}}, {{.C.Carding}}, {{.C.Markets}}, {{.C.PII_Leak}}, {{.C.Ransom}}, {{.C.Phishing}}, {{.C.Botnet}}, {{.C.Malware}}, {{.C.Exploit}}, {{.C.Crypto}}, {{.C.Counter}}, {{.C.Other}}], 
						backgroundColor: 'rgba(0, 243, 255, 0.2)',
						borderColor: '#00f3ff',
						pointBackgroundColor: '#ff003c'
					}] 
				}, 
				options: { 
					responsive: true, 
					maintainAspectRatio: false, 
					scales: { 
						r: { 
							angleLines: { color: '#333' },
							grid: { color: '#333' },
							pointLabels: { color: '#888', font: { size: 10 } },
							ticks: { display: false }
						} 
					},
					plugins: { legend: { display: false } }
				} 
			});
			
			var map = L.map('map').setView([20, 0], 2);
			L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { attribution: '' }).addTo(map);
			{{range .Data}}
			L.circleMarker([{{if eq .SourceCountry "Turkey"}}39{{else if eq .SourceCountry "Russia"}}61{{else}}20{{end}} + (Math.random()-0.5)*5, {{if eq .SourceCountry "Turkey"}}35{{else if eq .SourceCountry "Russia"}}105{{else}}0{{end}} + (Math.random()-0.5)*5], {color:'#ff003c', radius:4}).addTo(map);
			{{end}}
		</script>
	</body>
	</html>
	`
	
	type CatData struct { SQL_Inj, Carding, Markets, PII_Leak, Ransom, Phishing, Botnet, Malware, Exploit, Crypto, Counter, Other int }
	payload := struct { 
		Data interface{} 
		Total, High, Med, Low int64 
		Progress int 
		C CatData 
	}{ 
		Data: data, Total: t, High: h, Med: m, Low: l, Progress: prog, 
		C: CatData{
			SQL_Inj: catStats["SQL_Inj"], Carding: catStats["Carding"], Markets: catStats["Markets"], 
			PII_Leak: catStats["PII_Leak"], Ransom: catStats["Ransom"], Phishing: catStats["Phishing"], 
			Botnet: catStats["Botnet"], Malware: catStats["Malware"], Exploit: catStats["Exploit"], 
			Crypto: catStats["Crypto"], Counter: catStats["Counter"], Other: catStats["Other"],
		},
	}
	
	tpl, _ := template.New("dash").Parse(tmpl)
	tpl.Execute(w, payload)
}

// ---------------------- SETTINGS ----------------------
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	rules := repository.GetRules()
	
	tmpl := `
	<!DOCTYPE html><html><head><title>SYSTEM CONFIG</title><link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet"><style>:root{--neon:#00f3ff;--alert:#ff003c;--bg:#020202;--panel:#0a0a0a}body{background:var(--bg);color:#ccc;font-family:'Share Tech Mono';padding:40px}.container{max-width:900px;margin:0 auto}h2{color:var(--neon);border-bottom:2px solid var(--neon);padding-bottom:10px;margin-bottom:30px}.form-card{background:var(--panel);border:1px solid #333;padding:25px;margin-bottom:30px}input,select{background:black;color:white;border:1px solid #444;padding:12px;width:40%}button{background:var(--neon);color:black;border:none;padding:13px 25px;cursor:pointer;font-weight:bold}.cat-item{background:var(--panel);border:1px solid #222;padding:15px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}.del-btn{background:#220000;color:var(--alert);border:1px solid var(--alert);padding:6px 15px;text-decoration:none;font-size:12px}.back-link{color:var(--neon);text-decoration:none;display:inline-block;margin-bottom:20px;border:1px solid var(--neon);padding:5px 15px}</style></head><body><div class="container"><a href="/dashboard" class="back-link">← DASHBOARD</a><h2>/// THREAT INTELLIGENCE CONFIGURATION</h2><div class="form-card"><form action="/settings/add" method="POST"><input type="text" name="keyword" placeholder="Signature (e.g. 'SQL Dump')" required> <select name="level"><option value="Yüksek">High Severity</option><option value="Orta">Medium Severity</option><option value="Düşük">Low Severity</option></select> <button type="submit">DEPLOY RULE</button></form></div><ul>{{range .}}<li class="cat-item"><div><span style="color:#444;margin-right:10px;">ID: {{.ID}}</span><span style="color:white;font-weight:bold;font-size:18px;">{{.Keyword}}</span> <span style="margin-left:10px;color:{{if eq .RiskLevel "Yüksek"}}#ff003c{{else if eq .RiskLevel "Orta"}}orange{{else}}#00ff00{{end}}">{{.RiskLevel}}</span></div><a href="/settings/delete?id={{.ID}}" class="del-btn">REVOKE</a></li>{{end}}</ul></div></body></html>`
	
	t, _ := template.New("settings").Parse(tmpl)
	t.Execute(w, rules)
}

// ---------------------- DETAIL ----------------------
func detailHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	allData := repository.GetAllData()
	var sel models.ScrapedData
	for _, d := range allData { if int(d.ID) == id { sel = d; break } }

	threats := strings.Split(sel.RiskEvidence, " || ")

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>PACKET INSPECTION #{{.Sel.ID}}</title>
		<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
		<style>
			:root { --neon: #00f3ff; --alert: #ff003c; --warn: #ffcc00; --bg: #050505; --panel: #0a0a0a; }
			body { background: var(--bg); color: #ccc; font-family: 'Share Tech Mono', monospace; margin: 0; padding: 20px; }
			.top-bar { border-bottom: 2px solid var(--neon); padding-bottom: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
			.grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
			.sidebar { background: var(--panel); border: 1px solid #333; padding: 20px; height: fit-content; }
			.info-row { margin-bottom: 15px; border-bottom: 1px dashed #333; padding-bottom: 5px; }
			.label { color: #666; font-size: 11px; display: block; letter-spacing: 1px; }
			.value { color: white; font-size: 15px; word-break: break-all; }
			.value.risk { font-size: 18px; font-weight: bold; color: var(--alert); }
			.main-panel { background: var(--panel); border: 1px solid #333; padding: 0; }
			.threat-table { width: 100%; border-collapse: collapse; margin-bottom: 0; }
			.threat-table th { background: #150000; color: var(--alert); text-align: left; padding: 10px; border-bottom: 1px solid var(--alert); }
			.threat-table td { padding: 10px; border-bottom: 1px solid #333; background: #0a0505; color: #ffcccc; font-family: 'Courier New'; font-size: 13px; }
			.tabs { display: flex; background: #111; border-bottom: 1px solid #333; margin-top: 20px; }
			.tab { padding: 10px 20px; cursor: pointer; color: #777; border-right: 1px solid #333; }
			.tab.active { background: #222; color: var(--neon); }
			.content-view { padding: 15px; height: 400px; overflow-y: auto; background: #000; }
			pre { margin: 0; color: #0f0; font-family: 'Courier New'; font-size: 13px; white-space: pre-wrap; }
			.btn { border: 1px solid var(--neon); color: var(--neon); padding: 5px 15px; text-decoration: none; display: inline-block; transition:0.3s; }
			.btn:hover { background: var(--neon); color: black; }
		</style>
	</head>
	<body>
		<div class="top-bar">
			<h2>/// INSPECTION MODULE: PACKET #{{.Sel.ID}}</h2>
			<a href="/dashboard" class="btn">RETURN TO CONSOLE</a>
		</div>
		<div class="grid">
			<div class="sidebar">
				<div class="info-row"><span class="label">TARGET SOURCE</span><span class="value">{{.Sel.SourceName}}</span></div>
				<div class="info-row"><span class="label">DETECTED IP</span><span class="value" style="color:var(--neon);">{{.Sel.SourceIP}}</span></div>
				<div class="info-row"><span class="label">ORIGIN</span><span class="value">{{.Sel.SourceCountry}} (Port: {{.Sel.SourcePort}})</span></div>
				<div class="info-row"><span class="label">SCAN TIME</span><span class="value">{{.Sel.ScanDate.Format "Mon, 02 Jan 15:04:05"}}</span></div>
				<div class="info-row"><span class="label">THREAT LEVEL</span><span class="value risk" style="color:{{if eq .Sel.CriticalityLevel "Yüksek"}}#ff003c{{else if eq .Sel.CriticalityLevel "Orta"}}orange{{else}}#00ff00{{end}}">{{.Sel.CriticalityLevel}}</span></div>
			</div>
			
			<div class="main-panel">
				<div style="padding:15px; background:#111; border-bottom:1px solid #333; font-weight:bold; color:white;">DETECTED THREAT SIGNATURES</div>
				<table class="threat-table">
					<thead><tr><th>SEVERITY / RULE</th><th>DETAILS</th></tr></thead>
					<tbody>
						{{range .Threats}}
						<tr class="threat-row"><td style="color:var(--alert);">⚠️ ALERT MATCH</td><td>{{.}}</td></tr>
						{{else}}
						<tr><td colspan="2" style="color:#0f0;">✅ No specific threat signatures detected in this packet.</td></tr>
						{{end}}
					</tbody>
				</table>
				<div class="tabs">
					<div class="tab active" onclick="show('raw', this)">RAW PAYLOAD</div>
					<div class="tab" onclick="show('hex', this)">HEX DUMP</div>
				</div>
				<div class="content-view">
					<div id="raw" style="display:block;"><pre>{{.Sel.RawContent}}</pre></div>
					<div id="hex" style="display:none;"><pre id="hexOut"></pre></div>
				</div>
			</div>
		</div>
		<script>
			function show(id, el) {
				document.getElementById('raw').style.display='none';
				document.getElementById('hex').style.display='none';
				document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
				document.getElementById(id).style.display='block';
				el.classList.add('active');
			}
			var raw = document.getElementById('raw').innerText;
			var out = "";
			for(var i=0; i<raw.length; i+=16) {
				var line = raw.slice(i, i+16);
				var hex = "";
				for(var j=0; j<line.length; j++) hex += line.charCodeAt(j).toString(16).padStart(2,'0') + " ";
				out += (i.toString(16).padStart(8,'0')) + "  " + hex.padEnd(48,' ') + "  |" + line.replace(/[^\x20-\x7E]/g, '.') + "|\n";
			}
			document.getElementById('hexOut').innerText = out;
		</script>
	</body>
	</html>
	`
	t, _ := template.New("detail").Parse(tmpl)
	t.Execute(w, struct{ Sel models.ScrapedData; Threats []string }{sel, threats})
}

func addRuleHandler(w http.ResponseWriter, r *http.Request) { repository.AddRule(r.FormValue("keyword"), r.FormValue("level")); http.Redirect(w, r, "/settings", http.StatusSeeOther) }
func deleteRuleHandler(w http.ResponseWriter, r *http.Request) { repository.DeleteRule(r.URL.Query().Get("id")); http.Redirect(w, r, "/settings", http.StatusSeeOther) }
func logoutHandler(w http.ResponseWriter, r *http.Request) { isAuthenticated = false; http.Redirect(w, r, "/", http.StatusSeeOther) }