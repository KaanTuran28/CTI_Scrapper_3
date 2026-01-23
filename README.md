# Interactive CTI Scraper & SOC Dashboard

Interactive CTI Scraper, Dark Web (.onion) kaynaklarından otonom şekilde siber tehdit verisi toplayan, elde edilen ham veriyi Regex ve Heuristic analiz motorlarıyla işleyerek aksiyon alınabilir istihbarata (Actionable Intelligence) dönüştüren ve sonuçları modern bir SOC Dashboard üzerinde görselleştiren bütünleşik bir Cyber Threat Intelligence (CTI) platformudur.

Bu proje, siber güvenlik analistlerinin manuel istihbarat toplama süreçlerini azaltmak, Dark Web tabanlı tehditleri daha hızlı ve sistematik şekilde analiz edebilmek ve farkındalık kazandırmak amacıyla geliştirilmiştir.

---

## Özellikler

### Dark Web Tabanlı Tehdit Toplama
- Tor ağı üzerinden .onion uzantılı kaynaklardan veri çekme  
- Gerçek Dark Web forumları ve servislerden istihbarat toplama  
- SOCKS5 proxy mimarisi ile anonim ve izole bağlantı  

### Asenkron ve Ölçeklenebilir Mimari
- Go (Golang) tabanlı goroutine yapısı  
- Aynı anda birden fazla hedefi tarayabilme  
- Arka planda taramalar devam ederken arayüzün akıcı çalışması  

### Akıllı Tehdit Analizi
- 12’den fazla tehdit kategorisinin tespiti:
  - SQL Injection  
  - Kredi Kartı Dolandırıcılığı (Fraud)  
  - Ransomware  
  - PII (Personally Identifiable Information) Leak  
  - Malware ve Credential Dump  
- Regex tabanlı imza motoru  
- False Positive oranını düşürmeye yönelik heuristic filtreleme  

### Interactive SOC Dashboard
- Canlı saldırı ve tehdit görselleştirmeleri  
- Tehdit yoğunluğu ve dağılımını gösteren grafikler  
- Anlık tarama logları ve olay akışı  
- Gerçek zamanlı tarama ilerleme durumu  

### Dinamik Tehdit İmzaları
- Web arayüzü üzerinden yeni Regex tabanlı tehdit kuralları ekleme  
- Mevcut verileri, kuralları güncelleme veya silme  
- Kod değişikliği yapmadan analiz motorunu genişletebilme  

### Veri Kalıcılığı ve Kayıt Yönetimi
- SQLite veritabanı kullanımı  
- Tüm tarama sonuçlarının ve analiz çıktılarının saklanması  
- Geçmiş tehdit verileri üzerinden inceleme ve korelasyon imkânı  

### Container Tabanlı Dağıtım
- Docker ile izole ve taşınabilir mimari  
- Sistem bağımlılığı olmadan çalışabilme  
- Test, demo ve eğitim ortamları için uygun yapı  

---
## Projeye ait ekran görüntüsü dashboard

<img width="1856" height="991" alt="Ekran görüntüsü 2026-01-22 191406" src="https://github.com/user-attachments/assets/2b5ebdb8-c9dd-4721-97ac-2c2f8f25fb41" />

---
## Projenin Amacı

- Dark Web üzerinde dağınık halde bulunan tehdit verilerini merkezi olarak toplamak  
- Ham veriyi analiz ederek operasyonel değeri olan istihbarata dönüştürmek  
- CTI analistlerinin manuel araştırma yükünü azaltmak  
- Eğitim, simülasyon ve CTI farkındalığı kazandırmak  

---

## Kurulum ve Kullanım

Bu uygulamanın doğru şekilde çalışabilmesi için Docker ve Tor altyapısının hazır olması gerekir ve veri tabanı kurulması gereklidir. Uygulama kendi Tor servisini başlatmaz, sistemde aktif olarak çalışan Tor bağlantısını kullanır.Docker ile proje başlatılmalı ve kayıtlar için veri tabanı aktif olmalıdır.

### 1. Gerekli Bileşenler
- Docker  
- Docker Compose  
- Tor Browser  
- DB Browser for SQLite  

### 2. Tor Browser’ın Başlatılması
- Tor Browser açılır  
- “Connect” butonuna basılarak Tor ağına bağlanılır  
- Bağlantı sağlandıktan sonra Tor Browser açık bırakılır  

Uygulama, Tor Browser’ın varsayılan SOCKS5 portu olan `127.0.0.1:9150` üzerinden Tor ağına çıkış yapar.  
Tor Browser kapatılırsa .onion sitelere erişim sağlanamaz.

### 3. Veritabanı Görüntüleme (Opsiyonel)
- DB Browser for SQLite açılır  
- Proje dizininde oluşan `.db` dosyası seçilerek veritabanı incelenebilir.  

### 4. Projenin Build Edilmesi ve Çalıştırılması
Proje dizininde aşağıdaki komut çalıştırılır:

```bash
docker-compose up --build
```

### 5. Giriş Bilgileri
- Kullanıcı Adı: admin
- Şifre: password
