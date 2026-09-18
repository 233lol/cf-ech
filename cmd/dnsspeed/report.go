package main

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// reportOptions controls the text output of the ranking table.
type reportOptions struct {
	Sort string // ranking key
	Top  int    // show only the N fastest endpoints (0 = all)
	Bar  bool   // draw a speed bar
	Wide bool   // also show the min/max columns
}

// Column limits of the text tables. 0 means "as wide as needed".
const (
	maxProviderWidth = 22
	maxHostWidth     = 30
	maxErrorWidth    = 60
	barWidth         = 16
)

// PrintRanking writes the speed ranking of all endpoints that answered.
func PrintRanking(w io.Writer, ranked []Result, opts reportOptions) {
	ok := make([]Result, 0, len(ranked))
	for _, r := range ranked {
		if r.OK {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		fmt.Fprintln(w, "没有任何端点测试成功，详见下方的失败列表。")
		fmt.Fprintln(w)
		return
	}
	if opts.Top > 0 && opts.Top < len(ok) {
		ok = ok[:opts.Top]
	}

	// The fastest endpoint of the table scales the speed bars.
	fastest := ok[0].Stats.Median

	header := []string{"#", "协议", "服务商", "服务器", "首查(含握手)", "中位", "平均", "P95"}
	right := []bool{true, false, false, false, true, true, true, true}
	if opts.Wide {
		header = append(header, "最小", "最大")
		right = append(right, true, true)
	}
	header = append(header, "抖动", "成功", "评分")
	right = append(right, true, true, true)
	if opts.Bar {
		header = append(header, "速度")
		right = append(right, false)
	}

	rows := make([][]string, 0, len(ok))
	for i, r := range ok {
		row := []string{
			strconv.Itoa(i + 1),
			r.Target.Proto,
			r.Target.Server.Provider,
			r.Target.Host(),
			formatDuration(r.Handshake),
			formatDuration(r.Stats.Median),
			formatDuration(r.Stats.Avg),
			formatDuration(r.Stats.P95),
		}
		if opts.Wide {
			row = append(row, formatDuration(r.Stats.Min), formatDuration(r.Stats.Max))
		}
		row = append(row,
			formatDuration(r.Stats.Stddev),
			fmt.Sprintf("%d/%d", r.Succeeded(), r.Attempts),
			formatDuration(r.Stats.Score()),
		)
		if opts.Bar {
			row = append(row, speedBar(r.Stats.Median, fastest, barWidth))
		}
		rows = append(rows, row)
	}

	fmt.Fprintf(w, "== 速度排名（按%s排序，%d 个端点，成功 %d 个）==\n\n", sortLabel(opts.Sort), len(ranked), len(ok))
	writeTable(w, header, right, rows, []int{0, 0, maxProviderWidth, maxHostWidth})
	fmt.Fprintln(w)
}

// PrintFailures lists the endpoints that could not be measured.
func PrintFailures(w io.Writer, ranked []Result) {
	failed := make([]Result, 0)
	for _, r := range ranked {
		if !r.OK {
			failed = append(failed, r)
		}
	}
	if len(failed) == 0 {
		return
	}

	rows := make([][]string, 0, len(failed))
	for _, r := range failed {
		rows = append(rows, []string{r.Target.Proto, r.Target.Server.Provider, r.Target.Host(), r.Err})
	}

	fmt.Fprintf(w, "== 失败端点（%d 个）==\n\n", len(failed))
	writeTable(w, []string{"协议", "服务商", "服务器", "错误"},
		[]bool{false, false, false, false}, rows,
		[]int{0, maxProviderWidth, maxHostWidth, maxErrorWidth})
	fmt.Fprintln(w)
}

// ProgressLine describes one finished endpoint for the live progress output.
func ProgressLine(r Result) string {
	if !r.OK {
		return "失败: " + r.Err
	}
	return fmt.Sprintf("中位 %-8s 平均 %-8s 成功 %d/%d",
		formatDuration(r.Stats.Median), formatDuration(r.Stats.Avg), r.Succeeded(), r.Attempts)
}

func sortLabel(key string) string {
	switch key {
	case "avg":
		return "平均延迟"
	case "p95":
		return "P95 延迟"
	case "min":
		return "最小延迟"
	case "score":
		return "中位延迟+抖动"
	default:
		return "中位延迟"
	}
}

// writeTable prints header and rows as an aligned plain text table. maxWidths
// caps individual columns (0 = unlimited); longer cells are truncated.
func writeTable(w io.Writer, header []string, right []bool, rows [][]string, maxWidths []int) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = displayWidth(h)
	}
	for i := range widths {
		if i < len(maxWidths) && maxWidths[i] > 0 && widths[i] > maxWidths[i] {
			widths[i] = maxWidths[i]
		}
	}

	cells := make([][]string, len(rows))
	for ri, row := range rows {
		cells[ri] = make([]string, len(header))
		for i := range header {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			if i < len(maxWidths) && maxWidths[i] > 0 {
				cell = truncate(cell, maxWidths[i])
			}
			if n := displayWidth(cell); n > widths[i] {
				widths[i] = n
			}
			cells[ri][i] = cell
		}
	}

	line := func(row []string) string {
		var b strings.Builder
		for i := range header {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(pad(row[i], widths[i], i < len(right) && right[i]))
		}
		return strings.TrimRight(b.String(), " ")
	}

	total := 0
	for i, width := range widths {
		if i > 0 {
			total++
		}
		total += width
	}

	fmt.Fprintln(w, line(header))
	fmt.Fprintln(w, strings.Repeat("-", total))
	for _, row := range cells {
		fmt.Fprintln(w, line(row))
	}
}

// formatDuration renders a duration for the text tables.
func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d < time.Millisecond:
		return fmt.Sprintf("%.0fµs", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

// ms converts a duration to milliseconds with three decimals.
func ms(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())) / 1000
}

// msString renders a duration in milliseconds for the CSV report.
func msString(d time.Duration) string {
	return strconv.FormatFloat(ms(d), 'f', 3, 64)
}

// speedBar draws a bar that is proportional to the query rate: the fastest
// endpoint fills the whole width.
func speedBar(d, fastest time.Duration, width int) string {
	if d <= 0 || fastest <= 0 {
		return ""
	}
	n := int(math.Round(float64(fastest) / float64(d) * float64(width)))
	if n < 1 {
		n = 1
	}
	if n > width {
		n = width
	}
	return strings.Repeat("█", n)
}

// displayWidth returns the number of terminal cells used by s. Characters of
// East Asian scripts and emoji are counted as two cells.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func runeWidth(r rune) int {
	if r < 0x20 || (r >= 0x7f && r < 0xa0) {
		return 0 // control characters
	}
	if isWideRune(r) {
		return 2
	}
	return 1
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115f, // Hangul Jamo
		r >= 0x2e80 && r <= 0xa4cf,   // CJK radicals, Kangxi, CJK, Yi
		r >= 0xac00 && r <= 0xd7a3,   // Hangul syllables
		r >= 0xf900 && r <= 0xfaff,   // CJK compatibility ideographs
		r >= 0xfe30 && r <= 0xfe6f,   // CJK compatibility forms
		r >= 0xff00 && r <= 0xff60,   // fullwidth forms
		r >= 0xffe0 && r <= 0xffe6,   // fullwidth signs
		r >= 0x1f300 && r <= 0x1f9ff, // emoji
		r >= 0x20000 && r <= 0x3fffd: // CJK extensions
		return true
	}
	return false
}

// pad pads s to width cells, truncating it when it is too long.
func pad(s string, width int, right bool) string {
	s = truncate(s, width)
	n := width - displayWidth(s)
	if n <= 0 {
		return s
	}
	if right {
		return strings.Repeat(" ", n) + s
	}
	return s + strings.Repeat(" ", n)
}

// truncate shortens s to width cells, appending an ellipsis when it was cut.
func truncate(s string, width int) string {
	if displayWidth(s) <= width {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := runeWidth(r)
		if w+rw > width-1 { // leave room for the ellipsis
			break
		}
		b.WriteRune(r)
		w += rw
	}
	b.WriteRune('…')
	return b.String()
}
