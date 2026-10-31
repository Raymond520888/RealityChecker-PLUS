package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"RealityChecker/internal/ui"
)

// executeCSV 从CSV文件批量检测域名
func (r *RootCmd) executeCSV(csvFile string) {
	// 检查文件是否存在
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

	// 读取CSV文件
	file, err := os.Open(csvFile)
	if err != nil {
		ui.PrintError(fmt.Sprintf("错误：无法打开CSV文件 '%s': %v", csvFile, err))
		return
	}
	defer file.Close()

	// 解析CSV
	reader := csv.NewReader(file)
	// 🔴 核心修复 1：关闭严格列数检查，允许残缺行存在
	reader.FieldsPerRecord = -1
	// 🔴 核心修复 2：允许非严格引号，防止因为引号未闭合导致整个解析失败
	reader.LazyQuotes = true

	// 改为逐行读取，不再使用 ReadAll
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

	// ❌ 显示广告的代码已被移除
}

// extractDomainsFromCSV 从CSV reader中逐行提取域名
func extractDomainsFromCSV(reader *csv.Reader) []string {
	var domains []string
	domainSet := make(map[string]bool) // 用于去重
	isFirstLine := true

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 遇到无法解析的行，直接跳过，不中断程序
			continue
		}

		// 跳过完全空的行
		if len(record) == 0 {
			continue
		}

		// 处理 UTF-8 BOM 并跳过表头
		if isFirstLine {
			isFirstLine = false
			if len(record) > 0 {
				record[0] = strings.TrimPrefix(record[0], "\ufeff")
			}
			// 如果第一列是 "IP"，说明是表头，跳过
			if strings.EqualFold(strings.TrimSpace(record[0]), "IP") {
				continue
			}
		}

		// 安全提取（至少要有3列才能取到 CERT_DOMAIN）
		if len(record) < 3 {
			continue
		}

		certDomain := strings.TrimSpace(record[2]) // CERT_DOMAIN列
		if certDomain == "" {
			continue
		}

		// 清理域名（移除引号等）
		certDomain = strings.Trim(certDomain, "\"")

		// 排除一些不需要的域名
		if shouldExcludeDomain(certDomain) {
			continue
		}

		// 去重
		if !domainSet[certDomain] {
			domains = append(domains, certDomain)
			domainSet[certDomain] = true
		}
	}

	return domains
}

// shouldExcludeDomain 判断是否应该排除某个域名
func shouldExcludeDomain(domain string) bool {
	// 1. 排除包含通配符(*)的域名
	if strings.Contains(domain, "*") {
		return true
	}

	// 2. 排除列表
	excludePatterns := []string{
		"localhost",
		"server.domain.com",
		"johnnasmalley.hostname",
		"Kubernetes Ingress Controller Fake Certificate",
		"CloudFlare Origin Certificate",
		"FortiGate",
		"Unspecified",
	}

	domainLower := strings.ToLower(domain)

	for _, pattern := range excludePatterns {
		if strings.Contains(domainLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// 3. 排除IP地址格式
	if strings.Contains(domain, ".") && !strings.Contains(domain, "..") {
		parts := strings.Split(domain, ".")
		if len(parts) == 4 {
			// 可能是IP地址，简单检查
			isIP := true
			for _, part := range parts {
				if len(part) > 3 {
					isIP = false
					break
				}
			}
			if isIP {
				return true // 是IP地址，排除
			}
		}
	}

	// 4. 排除无效域名（太短或包含特殊字符）
	if len(domain) < 3 {
		return true
	}

	// 5. 排除包含多个连续点的域名
	if strings.Contains(domain, "..") {
		return true
	}

	return false
}