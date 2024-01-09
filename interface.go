package main

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

//go:generate mockgen -source scanner.go -package main -destination mock_nuclei.go

// NucleiInterface abstracts all usage of Nuclei to enable clean unit testing and SDK upgrades
type NucleiInterface interface {
	RunScan(addresses []string, template templates.Template) (resultEvent []*output.ResultEvent, failureEvent []*output.InternalWrappedEvent, err error)
}
