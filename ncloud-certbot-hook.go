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
		log.Fatalf("설정 파일 로드 실패: %v", err)
	}

	access := &services.Access{
		AccessKey: cfg.AccessKey,
		SecretKey: cfg.SecretKey,
	}

	// Certbot에서 넘겨주는 환경 변수
	// - DNS-01 인증 시:
	//   CERTBOT_DOMAIN, CERTBOT_VALIDATION
	// - 인증서 발급/갱신 후 (deploy-hook):
	//   CERTBOT_DOMAIN, CERTBOT_CERT_PATH, CERTBOT_KEY_PATH, CERTBOT_FULLCHAIN_PATH, etc.
	domain := os.Getenv("CERTBOT_DOMAIN")
	validation := os.Getenv("CERTBOT_VALIDATION")
	path := os.Getenv("RENEWED_LINEAGE")
	keyPath := path + "/privkey.pem"
	certPath := path + "/cert.pem"
	chainPath := path + "/chain.pem"

	// hookType 에 따라 분기
	switch strings.ToLower(hookType) {
	case "auth":
		// 1) DNS-01 검증을 위해 TXT 레코드 등록
		if domain == "" || validation == "" {
			log.Println("[Error] auth-hook: CERTBOT_DOMAIN 또는 CERTBOT_VALIDATION이 비어있습니다.")
			os.Exit(1)
		}
		log.Println("[Info] Running auth-hook...", "_acme-challenge."+domain, validation)

		_, _, err := GlobalDNS.SetRecord(access, "_acme-challenge."+domain, "TXT", validation, 300, true)
		if err != nil {
			log.Fatalf("TXT 레코드 생성 실패: %v", err)
		}

		time.Sleep(time.Duration(cfg.SleepTime) * time.Second)

		log.Println("[Info] auth-hook 완료")

	case "cleanup":
		// 2) DNS 검증이 끝난 후 TXT 레코드 삭제
		if domain == "" || validation == "" {
			log.Println("[Error] cleanup-hook: CERTBOT_DOMAIN 또는 CERTBOT_VALIDATION이 비어있습니다.")
			os.Exit(1)
		}
		log.Println("[Info] Running cleanup-hook...")

		err := GlobalDNS.DeleteRecord(access, "_acme-challenge."+domain, "TXT", "")
		if err != nil {
			log.Fatalf("TXT 레코드 삭제 실패: %v", err)
		}
		log.Println("[Info] cleanup-hook 완료")

	case "deploy":
		// 3) 인증서가 발급/갱신된 후 -> NCP Certificate Manager에 등록
		if domain == "" || certPath == "" || keyPath == "" {
			log.Println("[Error] deploy-hook: CERTBOT_DOMAIN이이 비어있습니다.")
			os.Exit(1)
		}
		log.Println("[Info] Running deploy-hook...")

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
			log.Fatalf("Failed to read root.pem: %v", err)
		}

		// Convert PEM contents to strings
		keyString := string(key)
		certString := string(cert)
		chainString := string(chain)
		rootstring := string(root)

		_, err = CertificateManager.CreateExternalCertificate(access, domain, keyString, certString, chainString, rootstring)
		if err != nil {
			log.Fatalf("NCP Certificate Manager 등록 실패: %v", err)
		}
		log.Println("[Info] deploy-hook 완료")

	default:
		log.Fatalf("Unknown or missing --hook value: %s (must be one of: auth, cleanup, deploy)", hookType)
	}
}

/*
type RecordRequest struct {
	Host    string  `json:"host"`
	Type    string  `json:"type"`
	Content string  `json:"content"`
	TTL     int     `json:"ttl"`
	AliasId *string `json:"aliasId,omitempty"`
	LbId    *string `json:"lbId,omitempty"`
}

type RecordItem struct {
	RecordId string `json:"recordId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
}

type ListRecordsResponse struct {
	Total   int          `json:"totalElements"`
	Content []RecordItem `json:"content"`
}

// createCertificateRequest: NCP Cert Manager "외부 인증서 등록" 요청 바디 예시 구조
type createCertificateRequest struct {
	CertificateName string `json:"certificateName"` // NCP 콘솔에 표시될 인증서 이름
	CertificatePEM  string `json:"certificatePEM"`  // 서버 인증서 PEM
	PrivateKeyPEM   string `json:"privateKeyPEM"`   // 개인 키 PEM
	ChainPEM        string `json:"chainPEM"`        // 루트/중간 체인 PEM
}

// createCertificateResponse: 등록 후 응답 (간략화 예시)
type createCertificateResponse struct {
	CertificateNo int64  `json:"certificateNo"`
	ResultCode    string `json:"returnCode"`
	ResultMessage string `json:"returnMessage"`
	// 필요 시 다른 필드 추가
}

// addTXTRecord: NCP Global DNS에 TXT 레코드 등록 (Stub)
func addTXTRecord(cfg *Config.Config, domain, value string) error {
	// (1) domain 에 해당하는 Zone ID 찾기
	zoneID, err := findZone(cfg, domain)
	if err != nil {
		return fmt.Errorf("존 조회 실패: %v", err)
	}
	// Zone이 없으면 에러 처리
	if zoneID == "" {
		return fmt.Errorf("존이 존재하지 않습니다. (domain=%s)", domain)
	}

	// (2) TXT 레코드 생성
	method := "POST"
	uri := fmt.Sprintf("/ncpdns/record/%s", zoneID)
	endpoint := "https://globaldns.apigw.ntruss.com/dns/v1" + uri

	// 요청 바디 생성 (배열 형식)
	reqBody := []RecordRequest{
		{
			Host:    "_acme-challenge." + domain, // DNS-01 인증을 위한 이름
			Type:    "TXT",
			Content: value,
			TTL:     300,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("JSON 마샬링 실패: %v", err)
	}

	req, err := http.NewRequest(method, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("HTTP 요청 생성 실패: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := setNcpApiHeaders(cfg, req, method, uri); err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP 요청 실패: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("레코드 생성 실패 (status=%d): %s", resp.StatusCode, string(respBody))
	}

	// (3) 응답 JSON 파싱 (필요 시 recordId 등 사용)
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("응답 JSON 파싱 실패: %v", err)
	}

	log.Printf("TXT 레코드 생성 성공: domain=%s, content=%s\n응답: %#v", domain, value, result)

	// 설정된 대기 시간만큼 대기
	time.Sleep(time.Duration(cfg.SleepTime) * time.Second)

	return nil
}

// deleteTXTRecord: NCP Global DNS에 TXT 레코드 삭제 (Stub)
func deleteTXTRecord(cfg *Config, domain, value string) error {
	log.Printf("deleteTXTRecord: domain=%s, value=%s\n", domain, value)

	// (1) Zone ID 찾기 (존이 없으면 에러)
	zoneID, err := findZone(cfg, domain)
	if err != nil {
		return fmt.Errorf("존 찾기 실패: %v", err)
	}
	if zoneID == "" {
		return fmt.Errorf("존이 존재하지 않아 레코드 삭제 불가 (domain=%s)", domain)
	}

	// (2) TXT 레코드 목록 조회
	method := "GET"
	uri := fmt.Sprintf("/ncpdns/record/%s", zoneID)
	endpoint := "https://globaldns.apigw.ntruss.com/dns/v1" + uri

	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return fmt.Errorf("HTTP 요청 생성 실패: %v", err)
	}
	if err := setNcpApiHeaders(cfg, req, method, uri); err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP 요청 실패: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("TXT 레코드 목록 조회 실패 (status=%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var listResp struct {
		Content []struct {
			RecordId string `json:"id"`
			Host     string `json:"host"`
			Type     string `json:"type"`
			Content  string `json:"content"`
		} `json:"content"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return fmt.Errorf("JSON 디코드 실패: %v", err)
	}

	// (3) '_acme-challenge.<domain>' & value가 일치하는 레코드 검색
	var targetRecordId string
	for _, r := range listResp.Content {
		if r.Type == "TXT" &&
			r.Host == "_acme-challenge."+domain &&
			r.Content == value {
			targetRecordId = r.RecordId
			break
		}
	}

	if targetRecordId == "" {
		log.Printf("일치하는 TXT 레코드를 찾지 못했습니다. (domain=%s, value=%s)\n", domain, value)
		return nil // 찾지 못했으면 단순 스킵 or 에러 반환도 가능
	}

	// (4) 레코드 삭제 요청 (DELETE로 삭제)
	delMethod := "DELETE"
	delUri := fmt.Sprintf("/ncpdns/record/%s", zoneID)
	delEndpoint := "https://globaldns.apigw.ntruss.com/dns/v1" + delUri

	// 요청 바디에 삭제할 레코드 ID를 배열로 포함
	reqBody := []string{targetRecordId}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("JSON 마샬링 실패: %v", err)
	}

	delReq, err := http.NewRequest(delMethod, delEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("레코드 삭제 요청 실패: %v", err)
	}
	delReq.Header.Set("Content-Type", "application/json")
	if err := setNcpApiHeaders(cfg, delReq, delMethod, delUri); err != nil {
		return err
	}

	delResp, err := client.Do(delReq)
	if err != nil {
		return fmt.Errorf("레코드 삭제 API 실패: %v", err)
	}
	defer delResp.Body.Close()

	if delResp.StatusCode != http.StatusOK && delResp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(delResp.Body)
		return fmt.Errorf("레코드 삭제 실패 (status=%d): %s", delResp.StatusCode, string(bodyBytes))
	}

	log.Printf("TXT 레코드 삭제 성공: recordId=%s, domain=%s, value=%s\n", targetRecordId, domain, value)
	return nil
}

// registerCertificate: NCP Certificate Manager에 외부 인증서 등록
func registerCertificate(cfg *Config, domain, certPath, keyPath string) (string, error) {
	log.Printf("[Info] registerCertificate: domain=%s, certPath=%s, keyPath=%s\n", domain, certPath, keyPath)

	// (1) 파일에서 PEM 내용 읽기
	//  - 서버 인증서 PEM (certPath)
	//  - 개인 키 PEM (keyPath)
	//  - Root CA PEM (/etc/ssl/certs/ISRG_Root_X1.pem)
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("인증서 파일(%s) 읽기 실패: %v", certPath, err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("개인 키 파일(%s) 읽기 실패: %v", keyPath, err)
	}

	rootCAPath := "/etc/ssl/certs/ISRG_Root_X1.pem"
	rootCAData, err := os.ReadFile(rootCAPath)
	if err != nil {
		return "", fmt.Errorf("Root CA 파일(%s) 읽기 실패: %v", rootCAPath, err)
	}

	// 만약 중간 체인(예: chain.pem)도 필요하다면 추가로 읽어와서 chainPEM에 합쳐주는 것이 권장됩니다.
	// 여기서는 "Root CA만 추가"한다는 요구사항에 맞춰 간단히 처리.
	chainPEM := string(rootCAData)

	// (2) API 요청 바디 구성
	reqBody := createCertificateRequest{
		// NCP Cert Manager 콘솔에 표시될 "인증서 이름"으로 domain을 사용 (원하는 명칭으로 지정 가능)
		CertificateName: domain,
		CertificatePEM:  string(certData),
		PrivateKeyPEM:   string(keyData),
		ChainPEM:        chainPEM,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("JSON 마샬링 실패: %v", err)
	}

	// (3) NCP Cert Manager API 엔드포인트
	//     실제 엔드포인트는 문서(https://api.ncloud-docs.com/docs/en/certificate-manager-certificate) 기준
	//     POST /certificate/v1/certificates
	method := "POST"
	uri := "	/certificate/withExternal"
	endpoint := "https://certificatemanager.apigw.ntruss.com/api/v1" + uri

	httpReq, err := http.NewRequest(method, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("HTTP 요청 생성 실패: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// (4) NCP API Gateway 시그니처 V2 헤더 설정
	if err := setNcpApiHeaders(cfg, httpReq, method, uri); err != nil {
		return "", err
	}

	// (5) 요청 전송
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("HTTP 요청 실패: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("인증서 등록 실패 (status=%d): %s", resp.StatusCode, string(respBody))
	}

	// (6) 응답 파싱
	var result createCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("응답 JSON 파싱 실패: %v", err)
	}

	if result.ResultCode != "SUCCESS" && result.CertificateNo == 0 {
		return "", fmt.Errorf("인증서 등록 실패 (code=%s): %s", result.ResultCode, result.ResultMessage)
	}

	certNoStr := strconv.FormatInt(result.CertificateNo, 10)
	log.Printf("NCP Certificate 등록 성공: certificateNo=%s\n", certNoStr)

	// (7) certificateNo 문자열로 반환
	return certNoStr, nil
}
*/
