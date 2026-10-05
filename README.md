# Interactive CTI Scraper & SOC Dashboard

![Go](https://img.shields.io/badge/Go-00ADD8)
![SQLite](https://img.shields.io/badge/SQLite-003B57)
![Docker](https://img.shields.io/badge/Docker-2496ED)
![Tor](https://img.shields.io/badge/network-Tor-7D4698)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

An integrated Cyber Threat Intelligence (CTI) platform that autonomously collects threat data from Dark Web (`.onion`) sources, turns the raw data into actionable intelligence with regex and heuristic analysis engines, and visualises the results on a modern SOC dashboard. It is built to reduce analysts' manual research load and to help study Dark Web threats more systematically.

![Dashboard](https://github.com/user-attachments/assets/2b5ebdb8-c9dd-4721-97ac-2c2f8f25fb41)

### Features

- **Dark Web collection:** pulls data from `.onion` sources over the Tor network through a SOCKS5 proxy, for anonymous, isolated connections.
- **Asynchronous, scalable architecture:** Go goroutines scan multiple targets at once while the UI stays responsive.
- **Smart threat analysis:** detects 12+ threat categories (SQL injection, payment fraud, ransomware, PII leaks, malware and credential dumps, …) with a regex signature engine and heuristic filtering to cut false positives.
- **Interactive SOC dashboard:** live threat visualisations, distribution charts, real-time scan logs and progress.
- **Dynamic threat signatures:** add, update or delete regex-based rules from the web UI — extend the analysis engine without changing code.
- **Persistence:** SQLite stores all scan results and analysis output for later review and correlation.
- **Containerised:** runs in isolation via Docker, portable and dependency-free.

### Goals

- Centralise threat data that is scattered across the Dark Web.
- Convert raw data into operationally useful intelligence.
- Reduce the manual research burden on CTI analysts.
- Serve as training, simulation and CTI-awareness material.

### Requirements

- Docker and Docker Compose
- Tor Browser (the app does not start its own Tor service — it uses the running one)
- DB Browser for SQLite (optional, to inspect the database)

### Setup

1. **Start Tor Browser** and click "Connect". Leave it open — the app exits to Tor through its default SOCKS5 port `127.0.0.1:9150`. If Tor Browser is closed, `.onion` sites are unreachable.
2. **(Optional) Inspect the DB:** open the generated `.db` file in DB Browser for SQLite.
3. **Build and run:**

   ```bash
   docker-compose up --build
   ```

4. **Login:** username `admin`, password `password` (change these before any real use).

> For authorised CTI research, defensive monitoring and education only.

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Dark Web (`.onion`) kaynaklarından otonom şekilde siber tehdit verisi toplayan, ham veriyi regex ve heuristic analiz motorlarıyla işleyip aksiyon alınabilir istihbarata dönüştüren ve sonuçları modern bir SOC Dashboard üzerinde görselleştiren bütünleşik bir CTI platformu. Analistlerin manuel istihbarat yükünü azaltmak ve Dark Web tabanlı tehditleri daha sistematik analiz etmek için geliştirildi.

![Dashboard](https://github.com/user-attachments/assets/2b5ebdb8-c9dd-4721-97ac-2c2f8f25fb41)

### Özellikler

- **Dark Web tabanlı toplama:** Tor ağı üzerinden `.onion` kaynaklardan, SOCKS5 proxy ile anonim ve izole bağlantıyla veri çeker.
- **Asenkron ve ölçeklenebilir mimari:** Go goroutine'leriyle aynı anda birden fazla hedefi tarar; arka planda tarama sürerken arayüz akıcı kalır.
- **Akıllı tehdit analizi:** 12'den fazla tehdit kategorisini (SQL Injection, ödeme dolandırıcılığı, ransomware, PII sızıntısı, malware ve credential dump, …) regex imza motoru ve false-positive'i düşüren heuristic filtreleme ile tespit eder.
- **Interactive SOC Dashboard:** canlı tehdit görselleştirmeleri, dağılım grafikleri, anlık tarama logları ve ilerleme durumu.
- **Dinamik tehdit imzaları:** web arayüzünden regex tabanlı kural ekleme, güncelleme veya silme — kod değişikliği olmadan analiz motorunu genişletme.
- **Veri kalıcılığı:** SQLite tüm tarama sonuçlarını ve analiz çıktılarını saklar; geçmiş veriler üzerinde inceleme ve korelasyon.
- **Container tabanlı dağıtım:** Docker ile izole, taşınabilir ve sistem bağımlılığı olmadan çalışır.

### Amaç

- Dark Web'de dağınık tehdit verilerini merkezi olarak toplamak.
- Ham veriyi operasyonel değeri olan istihbarata dönüştürmek.
- CTI analistlerinin manuel araştırma yükünü azaltmak.
- Eğitim, simülasyon ve CTI farkındalığı materyali olmak.

### Gereksinimler

- Docker ve Docker Compose
- Tor Browser (uygulama kendi Tor servisini başlatmaz, çalışan Tor bağlantısını kullanır)
- DB Browser for SQLite (opsiyonel, veritabanını incelemek için)

### Kurulum

1. **Tor Browser'ı başlatın** ve "Connect" ile ağa bağlanın. Açık bırakın — uygulama varsayılan SOCKS5 portu `127.0.0.1:9150` üzerinden Tor ağına çıkar. Tor Browser kapatılırsa `.onion` sitelere erişilemez.
2. **(Opsiyonel) Veritabanı:** oluşan `.db` dosyasını DB Browser for SQLite ile açıp inceleyebilirsiniz.
3. **Build ve çalıştırma:**

   ```bash
   docker-compose up --build
   ```

4. **Giriş:** kullanıcı adı `admin`, şifre `password` (gerçek kullanımdan önce değiştirin).

> Yalnızca yetkili CTI araştırması, savunma amaçlı izleme ve eğitim için.

### Lisans

MIT — bkz. [LICENSE](./LICENSE).
