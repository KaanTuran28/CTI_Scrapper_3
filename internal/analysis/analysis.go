package analysis

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/net/proxy"
)

const torProxyAddr = "host.docker.internal:9150"

func AnalyzeContent(targetURL string) (string, string) {
	dialer, err := proxy.SOCKS5("tcp", torProxyAddr, nil, proxy.Direct)
	if err != nil {
		return "TOR HATA", fmt.Sprintf("Tor Proxy Hatası: %v", err)
	}

	httpTransport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   90 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return "ERİŞİM HATASI", fmt.Sprintf("Siteye ulaşılamadı: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "OKUMA HATASI", "Veri okunamadı."
	}
	htmlContent := string(body)

	title := "Başlık Yok"
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(htmlContent)
	if len(matches) > 1 {
		title = matches[1]
	}

	return title, htmlContent
}

func GenerateMetadata() (string, string, string) {
	countries := []string{"Tor Exit Node", "Hidden Service", "Relay-France", "Relay-Germany", "Relay-Russia"}
	ports := []string{"80", "443", "8080"}
	return "127.0.0.1 (Masked)", countries[rand.Intn(len(countries))], ports[rand.Intn(len(ports))]
}