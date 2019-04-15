package mpsslcert

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	mp "github.com/mackerelio/go-mackerel-plugin-helper"
	"github.com/urfave/cli"
)

var OpenSSLPattern = regexp.MustCompile(
	`^notAfter=(.+)$`,
)

// SslCertPlugin for fetching metrics
type SslCertPlugin struct {
	// sslcert path
	Path string
}

// GraphDefinition Graph definition
func (c SslCertPlugin) GraphDefinition() map[string]mp.Graphs {
	// metric value structure
	var graphdef = map[string]mp.Graphs{
		"sslcert": {
			Label: ("days"),
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "days", Label: "days", Diff: false, Stacked: false},
			},
		},
	}
	return graphdef
}

// main function
func doMain(c *cli.Context) error {
	var sslcert SslCertPlugin
	sslcert.Path = c.Args().Get(0)

	helper := mp.NewMackerelPlugin(sslcert)
	helper.Run()
	return nil
}

// FetchMetrics fetch the metrics
func (c SslCertPlugin) FetchMetrics() (map[string]interface{}, error) {
	days, err := getSslCertMetrics(c.Path)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	result["days"] = days
	return result, nil
}

// Getting apache2 status from server-status module data.
func getSslCertMetrics(path string) (uint64, error) {
	cmd := exec.Command("/usr/bin/openssl", "x509", "-in", path, "-noout", "-dates")
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	var date string
	for _, line := range strings.Split(string(out), "\n") {
		if matches := OpenSSLPattern.FindStringSubmatch(line); matches != nil {
			date = matches[1]
		} else {
			continue
		}
	}
	t, _ := time.Parse("Jan 02 15:04:05 2006 GMT", date)
	days := time.Until(t).Hours() / 24
	return uint64(days), nil
}

// Do the plugin
func Do() {
	app := cli.NewApp()
	app.Name = "sslcert_metrics"
	app.Version = version
	app.Usage = "Get metrics from SSL cert."
	app.Author = "Fumihisa TONAKA"
	app.Email = "fumi.ftnk@gmail.com"
	app.Action = doMain
	app.Run(os.Args)
}
