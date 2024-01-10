package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	vulnreportdata "bitbucket.org/asecurityteam/vuln-report-data/v3"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"gopkg.in/yaml.v3"
)

const (
	unknown                  = `unknown`
	getAssetsByIPError       = `get-assets-by-ip-error`
	getAssetsByIPOmission    = `get-assets-by-ip-omission`
	scannerAssetIDFormat     = `%s_%s`
	customScannerTemplateKey = "customScannerTemplate"
	connectionRefused        = "connection refused"        // text that may appear in Nuclei InternalWrappedEvent["error"]
	contextDeadlineExceeded  = "context deadline exceeded" // text that may appear in Nuclei InternalWrappedEvent["error"]
)

var (
	fieldErrorRegexp = regexp.MustCompile(`not found in`)
)

type ScanRecord struct {
	ID          string // TODO: uuid instead?
	TemplateID  string
	Resource    string
	RequestedBy string
	Finished    *time.Time
	VulnReport  *vulnreportdata.VulnReport
}

// Scanner performs scans
type Scanner struct {
	Nuclei NucleiInterface
	LogFn  LogFn
	StatFn StatFn
}

// Scan performs the requested scans
func (s *Scanner) Scan(ctx context.Context, scanRecords []ScanRecord, templateStrings []string) ([]ScanRecord, error) {

	if s.Nuclei == nil {
		s.Nuclei = &Nuclei{}
	}

	stater := s.StatFn(ctx)

	// make sure all the templates we're given are parse-able and mapped
	templateMap := make(map[string]templates.Template)
	for _, templateString := range templateStrings {
		template := templates.Template{}
		if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
			errString := err.Error()
			if !fieldErrorRegexp.MatchString(errString) {
				return nil, err
			}
		}
		templateMap[template.ID] = template
	}

	scanSets := generateScanSets(scanRecords) // a:1,a:2,b:1,b:3 = 1:a,b 2:a 3:b

	for templateID, scanRecordsSet := range scanSets {

		scanRecordResults := make(map[string]bool)
		addresses := []string{}

		for _, scanRecord := range scanRecordsSet {
			resource := scanRecord.Resource
			resource = strings.ReplaceAll(resource, "http://", "")
			resource = strings.ReplaceAll(resource, "https://", "")
			addresses = append(addresses, scanRecord.Resource)
		}

		resultEvents, failureEvents, err := s.Nuclei.RunScan(addresses, templateMap[templateID])
		// a non-nil "err" here means Nuclei setup broke, and that's Very Very Bad so we return
		if err != nil {
			return nil, err
		}

		for _, resultEvent := range resultEvents {
			scanRecordID := getScanJobIDForResultEvent(resultEvent, scanRecords)
			scanRecordResults[scanRecordID] = true
			vulnReport := toVulnReportHit(resultEvent, scanRecordID, templateMap[templateID])
			for i, scanRecord := range scanRecords {
				if scanRecord.ID == scanRecordID {
					scanRecords[i].VulnReport = &vulnReport
					scanRecords[i].VulnReport.Asset.ScannerAssetID = fmt.Sprintf(scannerAssetIDFormat, scanRecord.Resource, templateID)
					if scanRecords[i].VulnReport.Asset.Metadata == nil {
						scanRecords[i].VulnReport.Asset.Metadata = make(map[string]interface{})
					}
					scanRecords[i].VulnReport.Asset.Metadata[vulnreportdata.WHO_REQUESTED_SCAN] = scanRecord.RequestedBy
					scanRecords[i].VulnReport.Asset.Metadata[customScannerTemplateKey] = templateID
					nowfinished := time.Now()
					scanRecords[i].Finished = &nowfinished
					break
				}
			}
			stater.Count("customscanner.vuln.hit", 1)
		}

		for _, failureEvent := range failureEvents {
			// I called them "failureEvent" here, but it's really a Nuclei "InternalWrappedEvent" which can be either
			// 1. a "failure to match"; meaning it was scanned and no vulns found, which is a good thing, or
			// 2. a "failure to reach"; meaning the host connection was refused, or we timed out before a response, or other
			scanRecordID := getScanJobIDForFailureEvent(failureEvent, scanRecords)
			// don't wipe out the resultEvent, which may have occurred against http or https
			if _, ok := scanRecordResults[scanRecordID]; !ok {
				vulnReport, err := s.toVulnReportMiss(failureEvent, scanRecordID)
				if err != nil {
					return nil, err
				}
				for i, scanRecord := range scanRecords {
					if scanRecord.ID == scanRecordID {
						scanRecords[i].VulnReport = &vulnReport
						scanRecords[i].VulnReport.Asset.ScannerAssetID = fmt.Sprintf(scannerAssetIDFormat, scanRecord.Resource, templateID)
						if scanRecords[i].VulnReport.Asset.Metadata == nil {
							scanRecords[i].VulnReport.Asset.Metadata = make(map[string]interface{})
						}
						scanRecords[i].VulnReport.Asset.Metadata[vulnreportdata.WHO_REQUESTED_SCAN] = scanRecord.RequestedBy
						scanRecords[i].VulnReport.Asset.Metadata[customScannerTemplateKey] = templateID
						nowfinished := time.Now()
						scanRecords[i].Finished = &nowfinished
						break
					}
				}
				if _, ok := vulnReport.Asset.Metadata["reachable"]; ok {
					// the conditional reads a bit strangely, but we trust that "toVulnReportMiss" places a {"reachable":false} metadata value
					stater.Count("customscanner.vuln.unreachable", 1, fmt.Sprintf("unreachableReason:%s", vulnReport.Asset.Metadata["unreachableReason"].(string)))
				} else { // else there is no "reachable" key at all
					stater.Count("customscanner.vuln.miss", 1)
				}
			}
		}
	}

	return scanRecords, nil

}

func generateScanSets(scanRecords []ScanRecord) map[string][]ScanRecord {
	// accumulate into sets to optimize the use of Nuclei

	templateMap := make(map[string][]ScanRecord) // a map of template ID to the hosts/addresses it goes with
	for _, scanRecord := range scanRecords {
		if templateMap[scanRecord.TemplateID] == nil {
			templateMap[scanRecord.TemplateID] = []ScanRecord{}
		}
		templateMap[scanRecord.TemplateID] = append(templateMap[scanRecord.TemplateID], scanRecord)
	}

	return templateMap

}

func getScanJobIDForResultEvent(re *output.ResultEvent, scanRecords []ScanRecord) string {
	for _, scanRecord := range scanRecords {
		if (scanRecord.Resource == re.Host || "http://"+scanRecord.Resource == re.Host || "https://"+scanRecord.Resource == re.Host || scanRecord.Resource == re.IP) && scanRecord.TemplateID == re.TemplateID {
			return scanRecord.ID
		}
	}
	return ``
}

func getScanJobIDForFailureEvent(failure *output.InternalWrappedEvent, scanRecords []ScanRecord) string {
	if failure == nil {
		return ``
	}
	ip := unknown
	if ipMapValue, ok := (failure.InternalEvent)["ip"]; ok {
		ip = ipMapValue.(string)
	}
	host := unknown
	if hostMapValue, ok := (failure.InternalEvent)["Hostname"]; ok { // yes, "Hostname" with a capital 'H'
		host = hostMapValue.(string)
	}
	templateID := unknown
	if templateIDMapValue, ok := (failure.InternalEvent)["template-id"]; ok {
		templateID = templateIDMapValue.(string)
	}

	for _, scanRecord := range scanRecords {
		if (scanRecord.Finished == nil) && ((scanRecord.Resource == ip || scanRecord.Resource == host) && scanRecord.TemplateID == templateID) {
			return scanRecord.ID
		}
	}
	return ``
}

func toVulnReportHit(re *output.ResultEvent, jobID string, template templates.Template) vulnreportdata.VulnReport {
	var vulnReport vulnreportdata.VulnReport

	vulnReport.ID = jobID

	hostname := re.Host

	// remove the leading schema bits from the Host if present
	rx := regexp.MustCompile("[a-z]+://(.*)")
	match := rx.FindStringSubmatch(re.Host)
	if match != nil {
		hostname = match[0]
		if len(match) == 2 {
			hostname = match[1]
		}
	}

	vulnReport.Asset = vulnreportdata.Asset{
		Hostnames: []string{hostname},
	}

	if re.IP != "" {
		vulnReport.Asset.IPAddresses = []string{re.IP}
	}

	scanType := vulnreportdata.SCAN_TYPE_NETWORK

	scanSourceName := vulnreportdata.SCAN_SOURCE_NAME_CUSTOM

	timestamp, isAlteredTimestamp := getTimestamp(re.Timestamp)

	metadata := map[string]interface{}{"Labels": template.Info.Tags.Value}

	if len(re.ExtractedResults) != 0 {
		// adding the extracted results i.e:extractors from nuclei template to the metadata
		// metadata["extractorName"] = re.ExtractorName
		metadata["extractedResults"] = re.ExtractedResults
	}

	if isAlteredTimestamp {
		metadata["alteredStartTime"] = "StartTime was altered due to Nuclei returning an empty time object"
	}

	vulnReport.Scan = vulnreportdata.Scan{
		StartTime: &timestamp,
		Source: &vulnreportdata.Source{
			Name: &scanSourceName,
			ID:   jobID,
		},
		Type: &scanType,
	}

	cvss := 0.0
	cveIDString := ""
	cvssMetric := ""
	severity := mapSeverityTextToInt(template.Info.SeverityHolder.Severity.String())
	if template.Info.Classification != nil {
		cvss = template.Info.Classification.CVSSScore
		if severity == "" && cvss == 0.0 {
			severity = "0"
		}
		if !template.Info.Classification.CVEID.IsEmpty() {
			cveIDString = template.Info.Classification.CVEID.String()
		}
		cvssMetric = template.Info.Classification.CVSSMetrics
	}

	if severity == "" && cvss != 0.0 {
		switch {
		case cvss > 0.0 && cvss < 4.0:
			severity = "1"
		case cvss >= 4.0 && cvss < 7.0:
			severity = "2"
		case cvss >= 7.0 && cvss < 9.0:
			severity = "3"
		case cvss >= 9.0 && cvss <= 10.0:
			severity = "4"
		}
	}

	vulnReport.Vulns = append(vulnReport.Vulns, vulnreportdata.Vuln{
		ID: template.ID,
		CVSS3: &vulnreportdata.CVSS{
			BaseScore: fmt.Sprintf("%.1f", cvss),
			Vector:    cvssMetric,
		},
		CVEs: []vulnreportdata.CVE{
			{
				ID: cveIDString,
			},
		},
		ScannerSeverity: severity,
		Description:     template.Info.Description,
		Title:           template.Info.Name,
		SeeAlso:         fmt.Sprintf("https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/%s.yaml", template.ID),
		Solutions: []vulnreportdata.Solution{
			{
				Description: template.Info.Remediation,
			},
		},
		Metadata: metadata,
	})

	return vulnReport
}

func (s *Scanner) toVulnReportMiss(failure *output.InternalWrappedEvent, jobID string) (vulnreportdata.VulnReport, error) {

	if failure == nil {
		return vulnreportdata.VulnReport{}, fmt.Errorf("Nuclei returned an empty InternalEvent")
	}
	var vulnReport vulnreportdata.VulnReport
	vulnReport.ID = jobID

	metadata := make(map[string]interface{})

	var ipAddresses []string
	if ipMapValue, ok := (failure.InternalEvent)["ip"]; ok {
		ipAddresses = []string{ipMapValue.(string)}
	}
	var hostnames []string
	if hostMapValue, ok := (failure.InternalEvent)["Hostname"]; ok { // yes, "Hostname" with a capital 'H'
		hostnames = []string{hostMapValue.(string)}
	}
	var datetime time.Time
	alteredStateReason := ""
	if dateMapValue, ok := (failure.InternalEvent)["date"]; ok {
		date := dateMapValue.(string)
		t, err := time.Parse(time.RFC1123, date)
		if err == nil {
			datetime = t
		} else {
			alteredStateReason = "StartTime was altered due to unparseable date"
		}
	} else {
		alteredStateReason = "StartTime was altered due to missing date in Nuclei response"
	}

	timestamp, isAlteredTimestamp := getTimestamp(datetime)
	if isAlteredTimestamp {
		metadata["alteredStartTime"] = alteredStateReason
	}

	// could also check failure.InternalEvent)["status_code"] == 0
	if errorText, ok := (failure.InternalEvent)["error"]; ok {
		errorTextString := errorText.(string)
		metadata["reachable"] = false
		if strings.Contains(errorTextString, connectionRefused) {
			metadata["unreachableReason"] = connectionRefused
		} else if strings.Contains(errorTextString, contextDeadlineExceeded) {
			metadata["unreachableReason"] = contextDeadlineExceeded
		}
	}

	vulnReport.Asset = vulnreportdata.Asset{
		IPAddresses: ipAddresses,
		Hostnames:   hostnames,
		Metadata:    metadata,
	}

	scanType := vulnreportdata.SCAN_TYPE_NETWORK

	scanSourceName := vulnreportdata.SCAN_SOURCE_NAME_CUSTOM
	vulnReport.Scan = vulnreportdata.Scan{
		StartTime: &timestamp,
		Source: &vulnreportdata.Source{
			Name: &scanSourceName,
			ID:   jobID,
		},
		Type: &scanType,
	}

	return vulnReport, nil
}

// getTimestamp returns time.Now() if timestamp is empty
func getTimestamp(timestamp time.Time) (time.Time, bool) {
	emptyTime := time.Time{}
	if timestamp == emptyTime {
		return time.Now(), true
	}

	return timestamp, false
}

func mapSeverityTextToInt(severity string) string {
	lowerSeverity := strings.ToLower(severity)
	switch lowerSeverity {
	case "critical":
		return "4"
	case "high":
		return "3"
	case "medium":
		return "2"
	case "low":
		return "1"
	case "info":
		return "0"
	default:
		return ""
	}
}
