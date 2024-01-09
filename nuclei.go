package main

import (
	"context"
	"io"
	"math"

	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
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

const (
	defaultTimeoutSeconds = 2
	maxTimeoutSeconds     = 5
	maxRedirects          = 5
)

// Nuclei implements the domain.Nuclei interface
type Nuclei struct {
	// TimeoutSeconds the Nuclei timeout (see "timeout" flag in docs: https://docs.projectdiscovery.io/tools/nuclei/running)
	// In this usage the default is 2, maximum 5.  Any value greater than 5 will be automatically adjusted down to 5.
	TimeoutSeconds  int
	HostErrorsCache hosterrorscache.CacheInterface
}

// RunScan executes a scan using Nuclei embedded library
func (n *Nuclei) RunScan(addresses []string, template templates.Template) (resultEvent []*output.ResultEvent, failureEvent []*output.InternalWrappedEvent, err error) {

	if n.TimeoutSeconds == 0 {
		n.TimeoutSeconds = defaultTimeoutSeconds
	}
	timeoutSeconds := int(math.Min(float64(n.TimeoutSeconds), maxTimeoutSeconds))

	if n.HostErrorsCache == nil {
		n.HostErrorsCache = &Cache{}
	}

	ctx := context.Background()

	if template.RequestsWithHTTP != nil {
		for i := range template.RequestsWithHTTP {
			template.RequestsWithHTTP[i].Redirects = true
			template.RequestsWithHTTP[i].MaxRedirects = maxRedirects
			template.RequestsWithHTTP[i].Signature = template.Signature
			// TODO: also SelfContained = true ??
		}
	}

	if template.RequestsHTTP != nil {
		for i := range template.RequestsHTTP {
			template.RequestsHTTP[i].Redirects = true
			template.RequestsHTTP[i].MaxRedirects = maxRedirects
			template.RequestsWithHTTP[i].Signature = template.Signature
			// TODO: also SelfContained = true ??
		}
	}

	defaultOpts := types.DefaultOptions()
	defaultOpts.Timeout = timeoutSeconds
	defaultOpts.Retries = 0
	// Critical setting so the Nuclei lib will call the writer for failed matches, so that we can differentiate
	// between "reachable with a hit", "reachable with a miss", and "unreachable".  Without this flag, we would not
	// receive a callback to the writer for "reachable with a miss".
	defaultOpts.MatcherStatus = true

	outputWriter := writer{}
	mockProgress := &testutils.MockProgressClient{}

	executerOpts := protocols.ExecutorOptions{
		Options:         defaultOpts,
		Output:          &outputWriter,
		Catalog:         &Catalog{},   // no-op Catalog, but we pass it because the Nuclei internals require one
		Progress:        mockProgress, // no-op Progress, but we pass it because the Nuclei internals require one
		RateLimiter:     ratelimit.NewUnlimited(ctx),
		ResumeCfg:       types.NewResumeCfg(),
		TemplateID:      template.ID,
		TemplateInfo:    template.Info,
		HostErrorsCache: n.HostErrorsCache,
	}

	// some weird init the library makes users call?
	executerOpts.CreateTemplateCtxStore()

	protocolsRequests := make([]protocols.Request, 0)
	for _, requestWithHTTP := range template.RequestsWithHTTP {
		protocolsRequests = append(protocolsRequests, requestWithHTTP)
	}
	template.Executer = tmplexec.NewTemplateExecuter(protocolsRequests, &executerOpts)

	// Must initialize all the global client connection pools before "Compile".
	// Would rather some default behavior here from the Nuclei lib.
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
		simpleInputProvider.Set(address) // yes the func name is "Set", but it actually "Add"s
	}

	// TODO: do we care about the boolean returned from the Execute func?
	_ = engine.Execute([]*templates.Template{&template}, &simpleInputProvider)
	engine.WorkPool().Wait() // Wait for the scan to finish

	return outputWriter.GetResults(), outputWriter.GetFailures(), nil

}

// Catalog is a no-op to satisfy Nuclei library requirements that a catalog
// exist and be passed to the lib.  Our abstracted use of Nuclei allows
// callers to pass their template as a function argument.
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

// NoopReportingClient is a no-op to satisfy Nuclei library requirements that a reporting client
// exist and be passed to the lib.  We don't _directly_ report anywhere in our usage, so no-op.
type NoopReportingClient struct{}

func (n *NoopReportingClient) RegisterTracker(tracker reporting.Tracker)    {}
func (n *NoopReportingClient) RegisterExporter(exporter reporting.Exporter) {}
func (n *NoopReportingClient) Close()                                       {}
func (n *NoopReportingClient) Clear()                                       {}
func (n *NoopReportingClient) CreateIssue(event *output.ResultEvent) error  { return nil }
func (n *NoopReportingClient) GetReportingOptions() *reporting.Options      { return nil }
