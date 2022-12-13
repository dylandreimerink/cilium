// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func main() {
	agent := generateMetricDocForCells(cmd.Agent)

	tpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		panic(err)
	}
	tpl.Execute(os.Stdout, struct {
		Agent string
	}{
		Agent: agent,
	})
}

//go:embed template/page.gotmpl
var pageTemplate string

type metricsIn struct {
	cell.In

	Metrics []metric.WithMetadata `group:"hive-metrics"`
}

func generateMetricDocForCells(cells ...cell.Cell) string {
	var agentMetrics []metric.WithMetadata

	cells = append(cells, cell.Invoke(func(min metricsIn) {
		agentMetrics = min.Metrics
	}))

	// Collect all metrics which are provided by the agent and the cells it depends on
	h := hive.New(
		cells...,
	)
	h.Populate()

	metricPerSubsystem := make(map[string]perSubsystem)
	for _, m := range agentMetrics {
		subsys := m.Opts().Subsystem
		key := subsys.Name

		// The metric truly has no category if no subsystem name and doc-name is set
		if subsys.Name == "" {
			if subsys.DocName == "" {
				key = "misc"
				subsys = metric.Subsystem{
					Name:    "",
					DocName: "Misc",
				}
			} else {
				// If we do have a doc-name, then the place it into its own category in the docs, but the metric
				// name will not be prefixed with anything.
				key = strings.Replace(strings.ToLower(subsys.DocName), " ", "_", -1)
			}
		}

		list := metricPerSubsystem[key]
		list.Subsystem = subsys
		list.Metrics = append(list.Metrics, m)
		list.Labels = make(map[string]metric.LabelDescription)

		metricPerSubsystem[key] = list
	}

	// Merge all label definitions per subsystem
	for _, mps := range metricPerSubsystem {
		for _, m := range mps.Metrics {
			lbls := m.Labels()
			for _, lbl := range lbls {
				desc := mps.Labels[lbl.Name]
				desc.Name = lbl.Name
				desc.Description = lbl.Description
				// Merge the known values
				for _, kv := range lbl.KnownValues {
					i := slices.IndexFunc(desc.KnownValues, func(dev metric.KnownValue) bool {
						return dev.Name == kv.Name
					})
					if i == -1 {
						desc.KnownValues = append(desc.KnownValues, kv)
					} else {
						if desc.KnownValues[i].Description == "" && kv.Description != "" {
							desc.KnownValues[i].Description = kv.Description
						}
					}
				}

				mps.Labels[lbl.Name] = desc
			}
		}

		// Don't display labels if no additional information is available
		for k, v := range mps.Labels {
			if v.Description == "" && len(v.KnownValues) == 0 {
				delete(mps.Labels, k)
			}
		}
	}

	var sb strings.Builder

	keys := maps.Keys(metricPerSubsystem)
	sort.Strings(keys)
	for _, key := range keys {
		subsystem := metricPerSubsystem[key]
		sb.WriteString(subsystem.Subsystem.DocName + "\n")
		sb.WriteString(strings.Repeat("~", len(subsystem.Subsystem.DocName)) + "\n")

		if subsystem.Subsystem.Description != "" {
			sb.WriteString(subsystem.Subsystem.Description + "\n\n")
		}

		var rows [][]string
		for _, metric := range subsystem.Metrics {
			var row []string
			opts := metric.Opts()

			if opts.Subsystem.Name != "" {
				row = append(row, fmt.Sprint("``", opts.Subsystem.Name, "_", opts.Name, "``"))
			} else {
				row = append(row, fmt.Sprint(opts.Name))
			}

			var labels []string
			for _, label := range metric.Labels() {
				labels = append(labels, fmt.Sprint("``", label.Name, "``"))
			}
			row = append(row, strings.Join(labels, ", "))

			row = append(row, opts.Description)

			if opts.EnabledByDefault {
				row = append(row, "Enabled")
			} else {
				row = append(row, "Disabled")
			}

			rows = append(rows, row)
		}

		sb.WriteString(metricTable(subsystem.Metrics))
		sb.WriteString("\n")

		if len(subsystem.Labels) > 0 {
			sb.WriteString(subsystem.Subsystem.DocName + " Labels\n")
			sb.WriteString(strings.Repeat("*", len(subsystem.Subsystem.DocName)) + "*******\n\n")

			sb.WriteString(labelTable(maps.Values(subsystem.Labels)))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

type perSubsystem struct {
	Subsystem metric.Subsystem
	Metrics   []metric.WithMetadata
	Labels    map[string]metric.LabelDescription
}

func metricTable(rows []metric.WithMetadata) string {
	header := []string{"Name", "Labels", "Default", "Description"}
	maxColWidth := make([]int, len(header))
	for i, str := range header {
		maxColWidth[i] = len(str)
	}

	var (
		rowNames  []string
		rowLabels []string
	)

	for _, row := range rows {
		opts := row.Opts()

		rowName := "``" + opts.Name + "``"
		if opts.Subsystem.Name != "" {
			rowName = "``" + opts.Subsystem.Name + "_" + opts.Name + "``"
		}
		rowNames = append(rowNames, rowName)
		if len(rowName) > maxColWidth[0] {
			maxColWidth[0] = len(rowName)
		}

		var labels []string
		for _, label := range row.Labels() {
			labels = append(labels, fmt.Sprint("``", label.Name, "``"))
		}
		rowLabel := strings.Join(labels, ", ")
		rowLabels = append(rowLabels, rowLabel)

		if len(rowLabel) > maxColWidth[1] {
			maxColWidth[1] = len(rowLabel)
		}

		maxColWidth[2] = len("Disabled")

		if len(opts.Description) > maxColWidth[3] {
			maxColWidth[3] = len(opts.Description)
		}
	}

	var b strings.Builder

	rowSep := func(rowSym string) {
		b.WriteString("+")
		for _, width := range maxColWidth {
			b.WriteString(strings.Repeat(rowSym, width))
			b.WriteString("+")
		}
		b.WriteString("\n")
	}

	rowSep("-")

	b.WriteString("|")
	for i, hdr := range header {
		b.WriteString(hdr)
		b.WriteString(strings.Repeat(" ", maxColWidth[i]-len(hdr)))
		b.WriteString("|")
	}
	b.WriteString("\n")

	rowSep("=")

	for i, row := range rows {
		b.WriteString("|")
		b.WriteString(rowNames[i])
		b.WriteString(strings.Repeat(" ", maxColWidth[0]-len(rowNames[i])))
		b.WriteString("|")
		b.WriteString(rowLabels[i])
		b.WriteString(strings.Repeat(" ", maxColWidth[1]-len(rowLabels[i])))
		b.WriteString("|")
		if row.Opts().EnabledByDefault {
			b.WriteString("Enabled ")
		} else {
			b.WriteString("Disabled")
		}
		b.WriteString("|")
		b.WriteString(row.Opts().Description)
		b.WriteString(strings.Repeat(" ", maxColWidth[3]-len(row.Opts().Description)))
		b.WriteString("|\n")

		rowSep("-")
	}

	return b.String()
}

func labelTable(labels metric.LabelDescriptions) string {
	header := []string{"Name", "Description", "Known Value", "Value Description"}
	maxColWidth := make([]int, len(header))
	for i, str := range header {
		maxColWidth[i] = len(str)
	}
	for _, row := range labels {
		if len("``"+row.Name+"``") > maxColWidth[0] {
			maxColWidth[0] = len("``" + row.Name + "``")
		}

		if len(row.Description) > maxColWidth[1] {
			maxColWidth[1] = len(row.Description)
		}

		for _, value := range row.KnownValues {
			if len("``"+value.Name+"``") > maxColWidth[2] {
				maxColWidth[2] = len("``" + value.Name + "``")
			}

			if len(value.Description) > maxColWidth[3] {
				maxColWidth[3] = len(value.Description)
			}
		}
	}

	var b strings.Builder

	fullSep := func(rowSym string) {
		b.WriteString("+")
		for _, width := range maxColWidth {
			b.WriteString(strings.Repeat(rowSym, width))
			b.WriteString("+")
		}
		b.WriteString("\n")
	}
	partialSep := func(rowSym string) {
		b.WriteString("|")
		for i, width := range maxColWidth {
			if i < 2 {
				b.WriteString(strings.Repeat(" ", width))
			} else {
				b.WriteString(strings.Repeat(rowSym, width))
			}

			if i < 1 {
				b.WriteString("|")
			} else {
				b.WriteString("+")
			}
		}
		b.WriteString("\n")
	}

	fullSep("-")

	b.WriteString("|")
	for i, hdr := range header {
		b.WriteString(hdr)
		b.WriteString(strings.Repeat(" ", maxColWidth[i]-len(hdr)))
		b.WriteString("|")
	}
	b.WriteString("\n")

	fullSep("=")

	for _, row := range labels {
		b.WriteString("|")
		b.WriteString("``" + row.Name + "``")
		b.WriteString(strings.Repeat(" ", maxColWidth[0]-len("``"+row.Name+"``")))
		b.WriteString("|")
		b.WriteString(row.Description)
		b.WriteString(strings.Repeat(" ", maxColWidth[1]-len(row.Description)))
		b.WriteString("|")
		if len(row.KnownValues) == 0 {
			b.WriteString(strings.Repeat(" ", maxColWidth[2]))
			b.WriteString("|")
			b.WriteString(strings.Repeat(" ", maxColWidth[3]))
			b.WriteString("|\n")
		} else {
			for i, value := range row.KnownValues {
				if i != 0 {
					partialSep("-")
					b.WriteString("|")
					b.WriteString(strings.Repeat(" ", maxColWidth[0]))
					b.WriteString("|")
					b.WriteString(strings.Repeat(" ", maxColWidth[1]))
					b.WriteString("|")
				}

				b.WriteString("``" + value.Name + "``")
				b.WriteString(strings.Repeat(" ", maxColWidth[2]-len("``"+value.Name+"``")))
				b.WriteString("|")
				b.WriteString(value.Description)
				b.WriteString(strings.Repeat(" ", maxColWidth[3]-len(value.Description)))
				b.WriteString("|")
				b.WriteString("\n")
			}
		}

		fullSep("-")
	}

	return b.String()
}

var metricsPerSubsystemTpl = `{{- $keys := sortStr (keys .) -}}
{{ range $index, $subsysName := $keys }}
{{- $list := index $ $subsysName }}
{{ $list.Subsystem.DocName }}
{{ repeat "~" (strlen $list.Subsystem.DocName) }}

{{ $hdr := strSlice "Name" "Labels" "Default" "Description" -}}
{{- $body := mkTblBody -}}

{{- if ne (len $list.Subsystem.Description) 0 -}}
  {{ $list.Subsystem.Description }}

{{ end -}}

{{- range $list.Metrics -}}
  {{- $opts := .Opts -}}
  {{- $labels := strSlice -}}
  {{- range .Labels -}}
    {{- $labels = appendSlice $labels (join "" (strSlice "` + "``" + `" .Name "` + "``" + `")) -}}
  {{- end -}}

  {{- $row := strSlice -}}
  {{- if gt (strlen $opts.Subsystem.Name) 0 -}}
    {{- $row = appendSlice $row (join "" (strSlice "` + "``" + `" (join "_" (strSlice $opts.Subsystem.Name $opts.Name)) "` + "``" + `")) -}}
  {{- else -}}
    {{- $row = appendSlice $row (join "" (strSlice "` + "``" + `" $opts.Name "` + "``" + `")) -}}
  {{- end -}}
  {{- $row = appendSlice $row (join ", " $labels) -}}
  {{- if $opts.EnabledByDefault -}}
    {{- $row = appendSlice $row "Enabled" -}}
  {{- else -}}
    {{- $row = appendSlice $row "Disabled" -}}
  {{- end -}}
  {{- if gt (strlen $opts.Description) 0 -}}
    {{- $row = appendSlice $row $opts.Description -}}
  {{- else -}}
    {{- $row = appendSlice $row $opts.Help -}}
  {{- end -}}

  {{- $body = appendSlice $body $row -}}
{{- end -}}
{{ table $hdr $body }}
{{- if ne (len $list.Labels) 0 }}
{{ $list.Subsystem.DocName }} Labels
{{ repeat "*" (strlen $list.Subsystem.DocName) }}*******

{{ end -}}
{{ range sortStr (keys $list.Labels) }}
  {{- $label := index $list.Labels . -}}
` + "``" + `{{- $label.Name }}` + "``" + ` {{ if ne (strlen $label.Description) 0 }}
{{- $label.Description }}

{{ end }}
  {{- $hdr := strSlice "Known Value" "Description" -}}
  {{- $body := mkTblBody -}}
  {{- range $label.KnownValues -}}
    {{- $body = appendSlice $body (strSlice (join "" (strSlice "` + "``" + `" .Name "` + "``" + `")) .Description) -}}
  {{- end -}}
  {{- if ne (len $body) 0 }}
{{- table $hdr $body }}
{{ end -}}
  {{- end -}}{{- /* range sortStr (keys $list.Labels) */ -}}
{{- end }}{{- /* range $index, $subsysName := $keys  */ -}}
`
