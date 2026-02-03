package main

import (
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"regexp"
"strings"
"sync"
"time"
)

var keywords = []string{
"patient records",
"medical data",
"health insurance",
"prescription",
"pharmacy database",
"hipaa",
"electronic health",
"patient list",
"medical records",
"credit card dump",
"pos malware",
"skimmer",
"fullz",
"card dump",
"retail breach",
"loyalty program",
"gift card",
"database leak",
"data dump",
"credentials",
"ssn",
"social security",
"dob",
"data breach",
}

var patterns = map[string]*regexp.Regexp{
"email":  regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
"ipv4":   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
"md5":    regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
"sha256": regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
}

type Finding struct {
Source      string    `json:"source"`
URL         string    `json:"url"`
Keyword     string    `json:"keyword,omitempty"`
IOCType     string    `json:"ioc_type,omitempty"`
IOCValue    string    `json:"ioc_value,omitempty"`
Snippet     string    `json:"snippet,omitempty"`
CollectedAt time.Time `json:"collected_at"`
}

func main() {
fmt.Println("==================================================")
fmt.Println("HRTIP Paste Monitor - Starting scan")
fmt.Printf("Time: %s\n", time.Now().UTC().Format(time.RFC3339))
fmt.Println("==================================================")

var allFindings []Finding
var mu sync.Mutex
var wg sync.WaitGroup

wg.Add(1)
go func() {
defer wg.Done()
findings := demonstrateDetection()
mu.Lock()
allFindings = append(allFindings, findings...)
mu.Unlock()
}()

wg.Wait()

fmt.Printf("\n[PasteMonitor] Total findings: %d\n", len(allFindings))
fmt.Println("==================================================")

if len(allFindings) > 0 {
output, _ := json.MarshalIndent(allFindings, "", "  ")
fmt.Println(string(output))
os.WriteFile("findings.json", output, 0644)
fmt.Println("\nSaved to: findings.json")
}
}

func scanURL(name, url string) []Finding {
var findings []Finding

client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Get(url)
if err != nil {
fmt.Printf("[%s] Error: %v\n", name, err)
return findings
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
if err != nil {
return findings
}

return analyzeContent(name, url, string(body))
}

func analyzeContent(source, url, content string) []Finding {
var findings []Finding
contentLower := strings.ToLower(content)

for _, keyword := range keywords {
if strings.Contains(contentLower, strings.ToLower(keyword)) {
snippet := extractSnippet(content, keyword, 50)
findings = append(findings, Finding{
Source:      source,
URL:         url,
Keyword:     keyword,
Snippet:     snippet,
CollectedAt: time.Now().UTC(),
})
fmt.Printf("[%s] Keyword match: %s\n", source, keyword)
}
}

for iocType, pattern := range patterns {
matches := pattern.FindAllString(content, 10)
for _, match := range matches {
if iocType == "email" && strings.Contains(match, "example.com") {
continue
}
findings = append(findings, Finding{
Source:      source,
URL:         url,
IOCType:     iocType,
IOCValue:    match,
CollectedAt: time.Now().UTC(),
})
}
}

return findings
}

func extractSnippet(content, keyword string, contextLen int) string {
lower := strings.ToLower(content)
idx := strings.Index(lower, strings.ToLower(keyword))
if idx == -1 {
return ""
}

start := idx - contextLen
if start < 0 {
start = 0
}
end := idx + len(keyword) + contextLen
if end > len(content) {
end = len(content)
}

return "..." + strings.TrimSpace(content[start:end]) + "..."
}

func demonstrateDetection() []Finding {
sampleData := `
THREAT INTEL REPORT - Paste Site Finding

Detected discussion about patient records breach.
Mentions of medical data exfiltration.
References to prescription database access.

IOCs found:
- IP: 45.33.32.156
- IP: 192.168.1.100
- Hash: 5d41402abc4b2a76b9719d911017c592
- Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
`

fmt.Println("[demo] Running detection on sample data...")
return analyzeContent("demo", "local://sample", sampleData)
}
