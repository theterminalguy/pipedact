package reporters

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// GenerateHTML produces a standalone HTML audit report.
func GenerateHTML(result *core.AuditResult) string {
	var sb strings.Builder

	scoreColor := "#10b981"
	if result.ComplianceScore < 70 {
		scoreColor = "#ef4444"
	} else if result.ComplianceScore < 90 {
		scoreColor = "#f59e0b"
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <title>pipedact Audit Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0f172a; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; }
  </style>
</head>
<body class="p-8 max-w-5xl mx-auto">
  <header class="flex items-center justify-between pb-6 border-b border-slate-800">
    <div class="flex items-center gap-3">
      <div class="text-3xl">🍁</div>
      <div>
        <h1 class="text-2xl font-bold">pipedact Audit Dossier</h1>
        <p class="text-sm text-slate-400">PIPEDA Schedule 1 Privacy-as-Code Compliance Report</p>
      </div>
    </div>
    <div class="text-right">
      <div class="text-xs text-slate-500">` + time.Now().Format("2006-01-02 15:04:05") + `</div>
      <div class="text-sm font-semibold text-slate-300">Jurisdiction: CA-PIPEDA</div>
    </div>
  </header>

  <section class="grid grid-cols-1 md:grid-cols-4 gap-4 my-8">
    <div class="p-5 bg-slate-900 border border-slate-800 rounded-xl">
      <span class="text-xs text-slate-400 uppercase font-semibold">Compliance Score</span>
      <div class="text-4xl font-black mt-1" style="color: ` + scoreColor + `">` + fmt.Sprintf("%d%%", result.ComplianceScore) + `</div>
      <span class="text-xs text-slate-400">` + html.EscapeString(result.ScoreLabel) + `</span>
    </div>
    <div class="p-5 bg-slate-900 border border-slate-800 rounded-xl">
      <span class="text-xs text-slate-400 uppercase font-semibold">Active Violations</span>
      <div class="text-4xl font-black text-rose-400 mt-1">` + fmt.Sprintf("%d", len(result.Violations)) + `</div>
      <span class="text-xs text-slate-400">Schedule 1 findings</span>
    </div>
    <div class="p-5 bg-slate-900 border border-slate-800 rounded-xl">
      <span class="text-xs text-slate-400 uppercase font-semibold">Files Scanned</span>
      <div class="text-4xl font-black text-indigo-400 mt-1">` + fmt.Sprintf("%d", result.ScannedFiles) + `</div>
      <span class="text-xs text-slate-400">` + fmt.Sprintf("%d", result.ScannedLines) + ` source lines</span>
    </div>
    <div class="p-5 bg-slate-900 border border-slate-800 rounded-xl">
      <span class="text-xs text-slate-400 uppercase font-semibold">CI Status</span>
      <div class="text-2xl font-bold mt-2 ` + (func() string {
		if result.Passed {
			return "text-emerald-400\">PASS (Exit 0)"
		}
		return "text-rose-400\">FAIL (Exit 1)"
	})() + `</div>
      <span class="text-xs text-slate-400">Completed in ` + fmt.Sprintf("%v", result.Duration) + `</span>
    </div>
  </section>

  <section class="my-8">
    <h2 class="text-xl font-bold mb-4">10 Fair Information Principles Status</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">`)

	var principleIDs []int
	for id := range result.PrincipleStatus {
		principleIDs = append(principleIDs, id)
	}
	sort.Ints(principleIDs)

	for _, id := range principleIDs {
		status := result.PrincipleStatus[id]
		p := status.Principle
		badge := `<span class="px-2 py-0.5 text-xs font-mono rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">PASS</span>`
		if !status.Passing {
			badge = `<span class="px-2 py-0.5 text-xs font-mono rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">ACTION REQUIRED</span>`
		}

		sb.WriteString(fmt.Sprintf(`
      <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div class="flex items-center justify-between mb-1">
          <span class="font-bold text-sm text-slate-200">%s</span>
          %s
        </div>
        <p class="text-xs text-slate-400 mb-2">%s</p>
        <div class="text-[11px] text-slate-500">Weight: %d%% • %s</div>
      </div>`, html.EscapeString(p.Name), badge, html.EscapeString(p.Meaning), p.Weight, html.EscapeString(p.Gate)))
	}

	sb.WriteString(`
    </div>
  </section>

  <section class="my-8">
    <h2 class="text-xl font-bold mb-4">Diagnostic Findings</h2>
    <div class="space-y-3">`)

	if len(result.Violations) == 0 {
		sb.WriteString(`<div class="p-6 bg-slate-900 border border-slate-800 rounded-lg text-emerald-400">No violations detected. All statutory gates passing!</div>`)
	} else {
		for i, v := range result.Violations {
			sb.WriteString(fmt.Sprintf(`
      <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div class="flex items-center justify-between mb-2">
          <span class="font-bold text-sm text-slate-200">#%d %s</span>
          <span class="px-2 py-0.5 text-xs font-mono rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">%s</span>
        </div>
        <div class="text-xs text-slate-400 mb-2">%s:%d</div>
        <div class="text-xs text-slate-300 mb-2">%s</div>
        <div class="p-2 bg-slate-950 font-mono text-xs text-slate-400 rounded border border-slate-800 mb-2">&gt; %s</div>
        <div class="text-xs text-emerald-400">Remedy: %s</div>
      </div>`, i+1, html.EscapeString(v.Principle), html.EscapeString(string(v.Severity)), html.EscapeString(v.FilePath), v.Line, html.EscapeString(v.Message), html.EscapeString(v.LineText), html.EscapeString(v.Remediation)))
		}
	}

	sb.WriteString(`
    </div>
  </section>
</body>
</html>`)

	return sb.String()
}
