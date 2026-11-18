package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"RealityChecker/internal/ui"
)

func (r *RootCmd) executeCSV(csvFile string) {
	if _, err := os.Stat(csvFile); os.IsNotExist(err) {
		ui.PrintErrorWithDetails(
			fmt.Sprintf("错误：CSV文件不存在 '%s'", csvFile),
			"请使用 RealiTLScanner 工具扫描，得到 CSV 文件",
			"命令：./RealiTLScanner -addr <VPS IP> -port 443 -thread 100 -timeout 5 -out file.csv",
			"（提示：RealiTLScanner 尽量在本地运行，不要在远端）",
			"（重要：多次运行时请更改输出文件名，如 file1.csv、file2.csv 等）",
		)
		return
	}

	file, err := os.Open(csvFile)
	if err != nil {
		ui.PrintError(fmt.Sprintf("错误：无法打开CSV文件 '%s': %v", csvFile, err))
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	domains := extractDomainsFromCSV(reader)
	if len(domains) == 0 {
		ui.PrintErrorWithDetails(
			"错误：未找到有效的域名",
			"请使用 RealiTLScanner 工具扫描，得到 CSV 文件",
			"命令：./RealiTLScanner -addr <VPS IP> -port 443 -thread 100 -timeout 5 -out file.csv",
			"（提示：RealiTLScanner 尽量在本地运行，不要在远端）",
			"（重要：多次运行时请更改输出文件名，如 file1.csv、file2.csv 等）",
		)
		return
	}

	fmt.Printf("[%s] 从CSV文件提取到 %d 个域名\n", time.Now().Format("15:04:05"), len(domains))
	ui.PrintTimestampedMessage("开始批量检测...")

	_, err = r.batchManager.CheckDomains(r.ctx, domains)
	if err != nil {
		fmt.Printf("批量检测失败: %v\n", err)
		return
	}
}

func extractDomainsFromCSV(reader *csv.Reader) []string {
	var domains []string
	domainSet := make(map[string]bool)
	isFirstLine := true

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) == 0 {
			continue
		}

		if isFirstLine {
			isFirstLine = false
			if len(record) > 0 {
				record[0] = strings.TrimPrefix(record[0], "\ufeff")
			}
			if strings.EqualFold(strings.TrimSpace(record[0]), "IP") {
				continue
			}
		}

		var certDomain string
		if len(record) >= 11 {
			certDomain = strings.TrimSpace(record[8])
		} else if len(record) >= 5 {
			certDomain = strings.TrimSpace(record[2])
		} else if len(record) >= 3 {
			certDomain = strings.TrimSpace(record[2])
		} else {
			continue
		}

		if certDomain == "" {
			continue
		}

		certDomain = strings.Trim(certDomain, "\"")

		if shouldExcludeDomain(certDomain) {
			continue
		}

		if !domainSet[certDomain] {
			domains = append(domains, certDomain)
			domainSet[certDomain] = true
		}
	}

	return domains
}

func shouldExcludeDomain(domain string) bool {
	if strings.Contains(domain, "*") {
		return true
	}

	domainLower := strings.ToLower(domain)

	blockedDomains := []string{
		"apple.com",
		"icloud.com",
		"tesla.com",
		"microsoft.com",
		"cloudflare.com",
	}
	for _, blocked := range blockedDomains {
		if domainLower == blocked || strings.HasSuffix(domainLower, "."+blocked) {
			return true
		}
	}

	excludePatterns := []string{
		"localhost",
		"server.domain.com",
		"johnnasmalley.hostname",
		"Kubernetes Ingress Controller Fake Certificate",
		"CloudFlare Origin Certificate",
		"FortiGate",
		"Unspecified",
	}

	for _, pattern := range excludePatterns {
		if strings.Contains(domainLower, strings.ToLower(pattern)) {
			return true
		}
	}

	if net.ParseIP(domain) != nil {
		return true
	}

	if len(domain) < 3 {
		return true
	}

	if strings.Contains(domain, "..") {
		return true
	}

	return false
}
