package main

import (
	"context"
	"fmt"
	"io"

	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

// documentation:
// https://github.com/projectdiscovery/nuclei/blob/main/DESIGN.md
// https://github.com/projectdiscovery/nuclei/issues/2214

// Nuclei implements the domain.Nuclei interface
type Nuclei struct {
}

// RunScan executes a scan using Nuclei embedded library
func (s *Nuclei) RunScan(addresses []string, template templates.Template) (resultEvent []*output.ResultEvent, failureEvent []*output.InternalWrappedEvent, err error) {

	ctx := context.Background()

	if template.RequestsWithHTTP != nil {
		for i := range template.RequestsWithHTTP {
			template.RequestsWithHTTP[i].Redirects = true
			template.RequestsWithHTTP[i].MaxRedirects = 5
			template.RequestsWithHTTP[i].Signature = template.Signature
			// TODO: also SelfContained = true ??
		}
	}

	if template.RequestsHTTP != nil {
		for i := range template.RequestsHTTP {
			template.RequestsHTTP[i].Redirects = true
			template.RequestsHTTP[i].MaxRedirects = 5
			template.RequestsWithHTTP[i].Signature = template.Signature
			// TODO: also SelfContained = true ??
		}
	}

	defaultOpts := types.DefaultOptions()
	defaultOpts.Timeout = 5
	defaultOpts.Retries = 0
	defaultOpts.MatcherStatus = true

	outputWriter := writer{}
	mockProgress := &testutils.MockProgressClient{}

	requestsWithHTTP := template.RequestsWithHTTP

	executerOpts := protocols.ExecutorOptions{
		Options:      defaultOpts,
		Output:       &outputWriter,
		Catalog:      &Catalog{},
		Progress:     mockProgress,
		RateLimiter:  ratelimit.NewUnlimited(ctx),
		ResumeCfg:    types.NewResumeCfg(),
		TemplateID:   template.ID,
		TemplateInfo: template.Info,
	}

	// some weird init the library makes users call?
	executerOpts.CreateTemplateCtxStore()

	// TODO this is just for demo/test.  In real code, we'd add all requestsWithHTTP, not just [0]
	template.Executer = tmplexec.NewTemplateExecuter([]protocols.Request{requestsWithHTTP[0]}, &executerOpts)

	// must initialize all the global client connection pools before "Compile"
	// would rather some default behavior here
	err = protocolinit.Init(defaultOpts)
	if err != nil {
		return nil, nil, err
	}

	template.Executer.Compile()
	template.TotalRequests = template.Executer.Requests()

	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		return nil, nil, err
	}
	executerOpts.WorkflowLoader = workflowLoader

	simpleInputProvider := inputs.SimpleInputProvider{}
	for _, address := range addresses {
		// TODO: uncomment
		// simpleInputProvider.Set(fmt.Sprintf("http://%s", address))
		simpleInputProvider.Set(fmt.Sprintf("https://%s", address))
	}

	_ = engine.Execute([]*templates.Template{&template}, &simpleInputProvider)
	engine.WorkPool().Wait() // Wait for the scan to finish

	return outputWriter.GetResults(), outputWriter.GetFailures(), nil

}

type Catalog struct{}

func (c *Catalog) OpenFile(filename string) (io.ReadCloser, error) {
	return nil, nil
}

func (c *Catalog) GetTemplatePath(target string) ([]string, error) {
	return nil, nil
}

func (c *Catalog) GetTemplatesPath(definitions []string) ([]string, map[string]error) {
	return nil, nil
}

func (c *Catalog) ResolvePath(templateName, second string) (string, error) {
	return "", nil
}

// ARES: this function is straight up copied from "github.com/projectdiscovery/nuclei/v2/pkg/templates"
// parseSelfContainedRequests parses the self contained template requests.
func parseSelfContainedRequests(template *templates.Template) {
	if template.Signature.Value.String() != "" {
		for _, request := range template.RequestsHTTP {
			request.Signature = template.Signature
		}
	}
	if !template.SelfContained {
		return
	}
	for _, request := range template.RequestsHTTP {
		request.SelfContained = true
	}
	for _, request := range template.RequestsNetwork {
		request.SelfContained = true
	}
}

type NoopReportingClient struct{}

func (n *NoopReportingClient) RegisterTracker(tracker reporting.Tracker)    {}
func (n *NoopReportingClient) RegisterExporter(exporter reporting.Exporter) {}
func (n *NoopReportingClient) Close()                                       {}
func (n *NoopReportingClient) Clear()                                       {}
func (n *NoopReportingClient) CreateIssue(event *output.ResultEvent) error  { return nil }
func (n *NoopReportingClient) GetReportingOptions() *reporting.Options      { return nil }
