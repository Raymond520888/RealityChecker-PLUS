package detectors

import (
	"fmt"
	"strings"

	"RealityChecker/internal/types"

	"github.com/projectdiscovery/cdncheck"
)

// CDNStage CDN检测阶段
type CDNStage struct {
	client *cdncheck.Client
}

// NewCDNStage 创建CDN检测阶段
func NewCDNStage() *CDNStage {
	// cdncheck.New() 只返回一个值，没有 error
	client := cdncheck.New()
	return &CDNStage{
		client: client,
	}
}

// Execute 执行CDN检测
func (cs *CDNStage) Execute(ctx *types.PipelineContext) error {
	return nil
}

// detectCDN 检测CDN
func (cs *CDNStage) detectCDN(domain string, networkResult *types.NetworkResult) (bool, string, string, string) {
	isMatched, provider, itemType, err := cs.client.CheckDomainWithFallback(domain)
	if err != nil {
		return false, "", "", ""
	}

	if !isMatched {
		return false, "", "", ""
	}

	confidence := "高"
	if itemType == "waf" || itemType == "cloud" {
		confidence = "中"
	}

	evidence := fmt.Sprintf("cdncheck 识别为 %s 提供商: %s", strings.ToUpper(itemType), provider)

	return true, provider, confidence, evidence
}

// CanEarlyExit 是否可以早期退出
func (cs *CDNStage) CanEarlyExit() bool {
	return false
}

// Priority 优先级
func (cs *CDNStage) Priority() int {
	return 8
}

// Name 阶段名称
func (cs *CDNStage) Name() string {
	return "cdn"
}
