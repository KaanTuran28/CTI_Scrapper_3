package repository

import (
	"log"
	"interactive-scraper/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

// İlerleme yüzdesini tutan küçük tablo
type ScanStatus struct {
	ID      uint `gorm:"primaryKey"`
	Percent int
}

func InitDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("darkweb_data.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("FATAL: Database connection failed: ", err)
	}
	db.AutoMigrate(&models.ScrapedData{}, &models.RiskRule{}, &ScanStatus{})
}

func SaveData(data models.ScrapedData) { db.Create(&data) }

func GetAllData() []models.ScrapedData {
	var data []models.ScrapedData
	db.Order("scan_date desc").Find(&data)
	return data
}

func GetStats() (int64, int64, int64, int64) {
	var t, h, m, l int64
	db.Model(&models.ScrapedData{}).Count(&t)
	db.Model(&models.ScrapedData{}).Where("criticality_level = ?", "Yüksek").Count(&h)
	db.Model(&models.ScrapedData{}).Where("criticality_level = ?", "Orta").Count(&m)
	db.Model(&models.ScrapedData{}).Where("criticality_level = ?", "Düşük").Count(&l)
	return t, h, m, l
}

func AddRule(k, l string) { db.Create(&models.RiskRule{Keyword: k, RiskLevel: l}) }
func GetRules() []models.RiskRule {
	var r []models.RiskRule
	db.Find(&r)
	return r
}
func DeleteRule(id string) { db.Delete(&models.RiskRule{}, id) }

func ClearAllData() {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.ScrapedData{})
	db.Model(&ScanStatus{}).Where("id = ?", 1).Update("percent", 0)
}

// --- İLERLEME (PROGRESS) FONKSİYONLARI ---

func SetScanProgress(p int) {
	var s ScanStatus
	if err := db.First(&s, 1).Error; err != nil {
		db.Create(&ScanStatus{ID: 1, Percent: p})
	} else {
		s.Percent = p
		db.Save(&s)
	}
}

func GetScanProgress() int {
	var s ScanStatus
	result := db.First(&s, 1)
	if result.Error != nil {
		return 0
	}
	return s.Percent
}