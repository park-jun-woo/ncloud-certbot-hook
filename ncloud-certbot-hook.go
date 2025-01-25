/*
ncloud-certbot-hook
Certbot DNS-01 Hook for Naver Cloud Platform

Copyright (c) 2023 [Your Name]

This software is released under the MIT License.
See the LICENSE file in the project root for details.
*/
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"parkjunwoo.com/ncloud-sdk-go/services"
	"parkjunwoo.com/ncloud-sdk-go/services/Networking/GlobalDNS"
	"parkjunwoo.com/ncloud-sdk-go/services/Security/CertificateManager"
)

type Config struct {
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	RootCAPath string `json:"root_ca_path"`
	SleepTime  int    `json:"sleep_time"`
}

// loadConfig: .config 파일에서 NCP 액세스 정보를 불러옴
func LoadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	// --hook 플래그 설정 (예: --hook=auth, --hook=cleanup, --hook=deploy)
	var hookType string
	flag.StringVar(&hookType, "hook", "", "Hook type to run (auth|cleanup|deploy)")

	// .config 파일 경로 지정(기본값: /etc/ncloud-certbot-hook/config.json)
	configFile := flag.String("config", "/etc/ncloud-certbot-hook/config.json", "NCP config file path")

	flag.Parse()

	// 설정 파일 로드
	cfg, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to load config.json: %v", err)
	}

	access := &services.Access{
		AccessKey: cfg.AccessKey,
		SecretKey: cfg.SecretKey,
	}

	// hookType 에 따라 분기
	switch strings.ToLower(hookType) {
	case "version":
		log.Println("ncloud-certbot-hook v1.0.0")
	case "auth":
		// 1) DNS-01 검증을 위해 TXT 레코드 등록
		domain := os.Getenv("CERTBOT_DOMAIN")
		validation := os.Getenv("CERTBOT_VALIDATION")
		if domain == "" || validation == "" {
			log.Println("[Error] auth-hook: CERTBOT_DOMAIN and CERTBOT_VALIDATION is empty.")
			os.Exit(1)
		}

		_, _, err := GlobalDNS.SetRecord(access, "_acme-challenge."+domain, "TXT", validation, 300, true)
		if err != nil {
			log.Fatalf("failed to create TXT record: %v", err)
		}

		time.Sleep(time.Duration(cfg.SleepTime) * time.Second)

	case "cleanup":
		// 2) DNS 검증이 끝난 후 TXT 레코드 삭제
		domain := os.Getenv("CERTBOT_DOMAIN")
		validation := os.Getenv("CERTBOT_VALIDATION")
		if domain == "" || validation == "" {
			log.Println("[Error] cleanup-hook: CERTBOT_DOMAIN and CERTBOT_VALIDATION is empty.")
			os.Exit(1)
		}

		err := GlobalDNS.DeleteRecord(access, "_acme-challenge."+domain, "TXT", "")
		if err != nil {
			log.Fatalf("failed to delete TXT record: %v", err)
		}

	case "deploy":
		// 3) 인증서가 발급/갱신된 후 -> NCP Certificate Manager에 등록
		path := os.Getenv("RENEWED_LINEAGE")
		keyPath := path + "/privkey.pem"
		certPath := path + "/cert.pem"
		chainPath := path + "/chain.pem"
		if path == "" {
			log.Println("[Error] deploy-hook: CERTBOT_DOMAIN is empty.")
			os.Exit(1)
		}
		domain := strings.ReplaceAll(path, "/etc/letsencrypt/live/", "")

		key, err := os.ReadFile(keyPath)
		if err != nil {
			log.Fatalf("Failed to read private.pem: %v", err)
		}

		cert, err := os.ReadFile(certPath)
		if err != nil {
			log.Fatalf("Failed to read cert.pem: %v", err)
		}

		chain, err := os.ReadFile(chainPath)
		if err != nil {
			log.Fatalf("Failed to read chain.pem: %v", err)
		}

		root, err := os.ReadFile(cfg.RootCAPath)
		if err != nil {
			log.Fatalf("Failed to read Root CA pem file: %v", err)
		}

		// Convert PEM contents to strings
		keyString := string(key)
		certString := string(cert)
		chainString := string(chain)
		rootstring := string(root)

		_, err = CertificateManager.CreateExternalCertificate(access, domain, keyString, certString, chainString, rootstring)
		if err != nil {
			log.Fatalf("failed to regist NCP Certificate Manager: %v", err)
		}

	default:
		log.Fatalf("Unknown or missing --hook value: %s (must be one of: auth, cleanup, deploy)", hookType)
	}
}
