package batch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/core"
	"RealityChecker/internal/report"
	"RealityChecker/internal/types"
)

type Manager struct {
	engine         *core.Engine
	formatter      *report.Formatter
	tableFormatter *report.TableFormatter
	config         *types.Config
	mu             sync.RWMutex
	running        bool
}

func NewManager(config *types.Config) *Manager {
	return &Manager{
		config:         config,
		formatter:      report.NewFormatter(config),
		tableFormatter: report.NewTableFormatter(config),
	}
}

func NewManagerWithEngine(engine *core.Engine, config *types.Config) *Manager {
	return &Manager{
		engine:         engine,
		config:         config,
		formatter:      report.NewFormatter(config),
		tableFormatter: report.NewTableFormatter(config),
	}
}

func (bm *Manager) Start() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.running {
		return fmt.Errorf("批量管理器已在运行")
	}

	if bm.engine == nil {
		bm.engine = core.NewEngine(bm.config)
		if err := bm.engine.Start(); err != nil {
			return fmt.Errorf("启动引擎失败: %v", err)
		}
	}

	bm.running = true
	return nil
}

func (bm *Manager) Stop() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if !bm.running {
		return nil
	}

	if bm.engine != nil {
		bm.engine.Stop()
	}

	bm.running = false
	return nil
}

func (bm *Manager) CheckDomains(ctx context.Context, domains []string) ([]*types.DetectionResult, error) {
	if !bm.running {
		return nil, fmt.Errorf("批量管理器未运行")
	}

	if len(domains) == 0 {
		return []*types.DetectionResult{}, nil
	}

	startTime := time.Now()

	results, err := bm.CheckDomainsWithProgress(ctx, domains)
	if err != nil {
		return nil, err
	}

	batchReport := bm.generateBatchReport(results, startTime, time.Now())
	fmt.Println(bm.formatBatchReport(batchReport))

	return results, nil
}

func (bm *Manager) CheckDomainsWithProgress(ctx context.Context, domains []string) ([]*types.DetectionResult, error) {
	results := make([]*types.DetectionResult, len(domains))
	resultChan := make(chan *ProgressResult, len(domains))

	go func() {
		defer close(resultChan)

		var wg sync.WaitGroup
		concurrency := int(bm.config.Concurrency.MaxConcurrent)
		semaphore := make(chan struct{}, concurrency)

		for i, domain := range domains {
			wg.Add(1)
			go func(index int, domain string) {
				defer wg.Done()

				select {
				case semaphore <- struct{}{}:
					defer func() {
						<-semaphore
					}()
				case <-ctx.Done():
					return
				}

				result, err := bm.engine.CheckDomain(ctx, domain)

				select {
				case resultChan <- &ProgressResult{
					Index:  index,
					Domain: domain,
					Result: result,
					Error:  err,
				}:
				case <-ctx.Done():
					return
				}
			}(i, domain)
		}

		wg.Wait()
	}()

	completed := 0
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	for completed < len(domains) {
		select {
		case progressResult := <-resultChan:
			completed++

			if progressResult.Error != nil {
				results[progressResult.Index] = progressResult.Result
				fmt.Printf("[%s] 正在检测 [%d/%d]: %s... 失败 - %v\n", time.Now().Format("15:04:05"), completed, len(domains), progressResult.Domain, progressResult.Error)
				continue
			}

			// 🚨 修复：获取最终展示的域名，优先取 FinalDomain，与 report 保持绝对一致！
			finalDomain := progressResult.Domain
			if progressResult.Result != nil {
				if progressResult.Result.Network != nil && progressResult.Result.Network.FinalDomain != "" {
					finalDomain = progressResult.Result.Network.FinalDomain
				} else if progressResult.Result.Domain != "" {
					finalDomain = progressResult.Result.Domain
				}
			}
			
			finalDomainLower := strings.ToLower(finalDomain)
			isBlocked := strings.Contains(finalDomainLower, "apple.com") ||
				strings.Contains(finalDomainLower, "tesla.com") ||
				strings.Contains(finalDomainLower, "microsoft.com") ||
				strings.Contains(finalDomainLower, "cloudflare.com")

			if isBlocked {
				results[progressResult.Index] = &types.DetectionResult{
					Domain:   finalDomain,
					Index:    progressResult.Index,
					Suitable: false,
					Error:    fmt.Errorf("命中黑名单，强制忽略"),
				}
				fmt.Printf("[%s] 正在检测 [%d/%d]: %s... 已忽略 (重定向至大厂 %s)\n", time.Now().Format("15:04:05"), completed, len(domains), progressResult.Domain, finalDomain)
				continue
			}

			results[progressResult.Index] = progressResult.Result

			fmt.Printf("[%s] 正在检测 [%d/%d]: %s... ", time.Now().Format("15:04:05"), completed, len(domains), progressResult.Domain)
			if progressResult.Result.Suitable {
				fmt.Printf("适合\n")
			} else {
				reason := "未知原因"
				if progressResult.Result.Error != nil {
					reason = progressResult.Result.Error.Error()
				}
				fmt.Printf("不适合 - %s\n", reason)
			}

		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			fmt.Printf("\n[%s] 检测超时，以下域名未完成检测：\n", time.Now().Format("15:04:05"))
			for i, domain := range domains {
				if results[i] == nil {
					fmt.Printf("  - %s (超时)\n", domain)
					results[i] = &types.DetectionResult{
						Domain:   domain,
						Index:    i,
						Suitable: false,
						Error:    fmt.Errorf("检测超时"),
					}
				}
			}
			return results, nil
		}
	}

	return results, nil
}

type ProgressResult struct {
	Index  int
	Domain string
	Result *types.DetectionResult
	Error  error
}

func (bm *Manager) CheckDomainsStream(ctx context.Context, domains []string) (<-chan *types.DetectionResult, error) {
	if !bm.running {
		return nil, fmt.Errorf("批量管理器未运行")
	}
	return bm.engine.CheckDomainsStream(ctx, domains)
}

func (bm *Manager) generateBatchReport(results []*types.DetectionResult, startTime, endTime time.Time) *types.BatchReport {
	stats := &types.Statistics{
		TotalDomains: len(results),
	}

	for _, result := range results {
		if result == nil {
			continue
		}

		if result.Error == nil {
			stats.SuccessfulChecks++
		} else {
			errorMsg := result.Error.Error()
			if strings.Contains(errorMsg, "域名被墙") || strings.Contains(errorMsg, "国内网站") {
				stats.SuccessfulChecks++
			} else {
				stats.FailedChecks++
			}
		}

		if result.Suitable {
			stats.SuitableDomains++
		}

		if result.Blocked != nil && result.Blocked.IsBlocked {
			stats.BlockedDomains++
		}
	}

	return &types.BatchReport{
		StartTime:     startTime,
		EndTime:       endTime,
		TotalDuration: endTime.Sub(startTime),
		Results:       results,
		Statistics:    stats,
		Summary: &types.BatchSummary{
			SuccessRate:     float64(stats.SuccessfulChecks) / float64(stats.TotalDomains),
			SuitabilityRate: float64(stats.SuitableDomains) / float64(stats.TotalDomains),
			BlockingRate:    float64(stats.BlockedDomains) / float64(stats.TotalDomains),
		},
	}
}

func (bm *Manager) formatBatchReport(report *types.BatchReport) string {
	var result strings.Builder

	result.WriteString(fmt.Sprintf(`
批量检测报告
总耗时: %s
检测域名: %d 个
成功率: %.1f%%
适合性率: %.1f%%

`,
		formatDuration(report.TotalDuration),
		report.Statistics.TotalDomains,
		report.Summary.SuccessRate*100,
		report.Summary.SuitabilityRate*100,
	))

	var suitableResults []*types.DetectionResult
	var unsuitableResults []*types.DetectionResult
	var excludedResults []*types.DetectionResult

	for _, domainResult := range report.Results {
		if domainResult == nil {
			continue
		}

		if domainResult.Suitable && domainResult.Error == nil {
			suitableResults = append(suitableResults, domainResult)
		} else {
			if domainResult.StatusCodeCategory == types.StatusCodeCategoryExcluded {
				excludedResults = append(excludedResults, domainResult)
			} else {
				unsuitableResults = append(unsuitableResults, domainResult)
			}
		}
	}

	if len(suitableResults) > 0 {
		bm.sortByRecommendationStars(suitableResults)
		result.WriteString("适合的域名:\n\n")
		result.WriteString(bm.tableFormatter.FormatSuitableTable(suitableResults))
		result.WriteString("\n")
	}

	if len(unsuitableResults) > 0 {
		result.WriteString(bm.tableFormatter.FormatUnsuitableSummary(unsuitableResults))
	}

	if len(excludedResults) > 0 {
		result.WriteString("\n")
		result.WriteString(bm.formatExcludedDomains(excludedResults))
	}

	return result.String()
}

func (bm *Manager) formatExcludedDomains(excludedResults []*types.DetectionResult) string {
	if len(excludedResults) == 0 {
		return ""
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("状态码不自然的域名 (%d个):\n", len(excludedResults)))

	statusCodeCounts := make(map[int]int)
	for _, domainResult := range excludedResults {
		if domainResult.Network != nil {
			statusCodeCounts[domainResult.Network.StatusCode]++
		}
	}

	var statusCodes []int
	for statusCode := range statusCodeCounts {
		statusCodes = append(statusCodes, statusCode)
	}
	sort.Ints(statusCodes)

	for _, statusCode := range statusCodes {
		count := statusCodeCounts[statusCode]
		result.WriteString(fmt.Sprintf("   - %d个状态码 %d\n", count, statusCode))
	}

	return result.String()
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Nanoseconds())/1000)
	} else if d < time.Second {
		return fmt.Sprintf("%.0fms", float64(d.Nanoseconds())/1000000)
	} else if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	} else {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
}

func (bm *Manager) sortByRecommendationStars(results []*types.DetectionResult) {
	sort.Slice(results, func(i, j int) bool {
		starsI := bm.calculateStars(results[i])
		starsJ := bm.calculateStars(results[j])
		return starsI < starsJ
	})
}

func (bm *Manager) calculateStars(result *types.DetectionResult) int {
	stars := 0

	if result.TLS != nil && result.TLS.SupportsTLS13 &&
		result.TLS.SupportsX25519 && result.TLS.SupportsHTTP2 &&
		result.SNI != nil && result.SNI.SNIMatch {
		stars++
	}

	if result.TLS != nil && result.TLS.HandshakeTime > 0 {
		handshakeMs := int(result.TLS.HandshakeTime.Milliseconds())
		if handshakeMs <= 200 {
			stars++
		}
	}

	if result.CDN == nil || !result.CDN.IsCDN {
		stars++
	}

	if result.CDN != nil && !result.CDN.IsHotWebsite {
		stars++
	}

	if result.Certificate != nil && result.Certificate.Valid {
		if result.Certificate.DaysUntilExpiry >= 60 {
			stars++
		}
	}

	return stars
}
