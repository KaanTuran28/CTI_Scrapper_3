package main

import (
	"io"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"interactive-scraper/internal/analysis"
	"interactive-scraper/internal/models"
	"interactive-scraper/internal/repository"
	"gopkg.in/yaml.v2"
)

func main() {
	repository.InitDB()
	
	logFile, _ := os.OpenFile("scan_report.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "", 0)

	data, err := os.ReadFile("targets.yaml")
	if err != nil {
		logger.Fatalf("Hata: %v", err)
	}
	var config models.TargetConfig
	yaml.Unmarshal(data, &config)

	logger.Println("=== CTI SERVICE INITIALIZED ===")
	logger.Println("=== MONITORING DARK WEB NODES (24/7) ===")

	for {
		rules := repository.GetRules()

		for _, target := range config.Targets {
			time.Sleep(2000 * time.Millisecond)

			status := "TARANDI" 
			
			title, content := analysis.AnalyzeContent(target.URL)
			
			ip, country, port := analysis.GenerateMetadata()

			finalScore := rand.Intn(4) + 1
			finalLevel := "Düşük"
			
			fullText := strings.ToLower(title + " " + content)
			
			for _, rule := range rules {
				if strings.Contains(fullText, strings.ToLower(rule.Keyword)) {
					switch rule.RiskLevel {
					case "Yüksek":
						finalScore = 9
						finalLevel = "Yüksek"
					case "Orta":
						finalScore = 6
						finalLevel = "Orta"
					}
					break
				}
			}

			if strings.Contains(title, "HATA") || strings.Contains(title, "ERROR") {
				status = "ERİŞİLEMEDİ"
				finalLevel = "Bilinmiyor"
			}

			newData := models.ScrapedData{
				SourceName:       target.Name,
				SourceURL:        target.URL,
				Title:            title,
				RawContent:       content,
				CriticalityScore: finalScore,
				CriticalityLevel: finalLevel,
				ScanDate:         time.Now(),
				Status:           status,
				SourceIP:         ip,
				SourceCountry:    country,
				SourcePort:       port,
			}
			repository.SaveData(newData)
			logger.Printf("[+] TARGET: %s | STATUS: %s | RISK: %s", target.Name, status, finalLevel)
		}

		logger.Println("=== SCAN CYCLE COMPLETE. SLEEPING FOR 60 SECONDS... ===")
		
		time.Sleep(60 * time.Second)
	}
}