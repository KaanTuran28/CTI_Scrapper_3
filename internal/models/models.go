package models

import (
	"time"
	"gorm.io/gorm"
)

type ScrapedData struct {
	gorm.Model
	SourceName       string
	SourceURL        string
	Title            string
	RawContent       string
	CriticalityScore int
	CriticalityLevel string
	ScanDate         time.Time
	Status           string
	MatchedKeyword   string
	RiskEvidence     string
	SourceIP         string
	SourceCountry    string
	SourcePort       string
}

type RiskRule struct {
	gorm.Model
	Keyword   string
	RiskLevel string
}

type Target struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Category string `yaml:"category"`
}

type TargetConfig struct {
	Targets []Target `yaml:"targets"`
}