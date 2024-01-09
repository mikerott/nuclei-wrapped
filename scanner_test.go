package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	commonmocks "bitbucket.org/asecurityteam/testing-toolbox/mocks"
	vulnreportdata "bitbucket.org/asecurityteam/vuln-report-data/v3"
	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/runhttp"
	"github.com/golang/mock/gomock"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/assert"
)

const RequestString = `
requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:

      - type: regex
        part: header
        regex:
          - "Apache+"

      - type: status
        status:
          - 200

    extractors:
      - type: kval
        part: header
        kval:
          - Server
`

func TestResultEventToVulnReport(t *testing.T) {

	// this test is for template hits; mocknuclei.EXPECT().RunScan should only ever return []*output.ResultEvent

	scanType := vulnreportdata.SCAN_TYPE_NETWORK
	scanSourceNameCustom := vulnreportdata.SCAN_SOURCE_NAME_CUSTOM

	tc := []struct {
		Name           string
		Data           []byte
		Mocks          func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger)
		ExpectedError  error
		ExpectedReturn vulnreportdata.VulnReport
	}{
		{
			Name: "Golden Path To Vuln Report",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "9.1",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "4",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "Golden Path To Vuln Report - No Classification",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "0.0",
							TemporalScore:  "",
							Vector:         "",
							TemporalVector: "",
						},
						ScannerSeverity: "",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "Golden Path To Vuln Report - Classification but No Data",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "0.0",
							TemporalScore:  "",
							Vector:         "",
							TemporalVector: "",
						},
						ScannerSeverity: "",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "Golden Path To Vuln Report - Severity",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  severity: high
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "9.1",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "3",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "Golden Path To Vuln Report - Low",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 0.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "0.1",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "1",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "Golden Path To Vuln Report - Medium",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 4.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "4.1",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "2",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "Golden Path To Vuln Report - High",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 7.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "7.1",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "3",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "no severity, cvss == 0.0",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 0.0
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "0.0",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "0",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
		{
			Name: "To Vuln Report Path - Nuclei returns empty timestamp",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"31.3.96.40"}, gomock.Any()).Return([]*output.ResultEvent{{Host: "localhost", TemplateID: "apache-detect", IP: "31.3.96.40", Timestamp: time.Now()}}, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.hit", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "31.3.96.40_apache-detect",
					IPAddresses:    []string{"31.3.96.40"},
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "customScannerTemplate": "apache-detect"},
				},
				Vulns: []vulnreportdata.Vuln{
					{
						Metadata:    map[string]interface{}{"Labels": []string{"bitbucket", "web", "community"}},
						ID:          "apache-detect",
						Title:       "Bitbucket Server: Path Travarsal via Migration Tool",
						Description: "Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n",
						CVEs: []vulnreportdata.CVE{
							{
								ID:          "cve-2019-3397",
								Description: "",
							},
						},
						CVSS: nil,
						CVSS3: &vulnreportdata.CVSS{
							BaseScore:      "9.1",
							TemporalScore:  "",
							Vector:         "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
							TemporalVector: "",
						},
						ScannerSeverity: "4",
						Solutions: []vulnreportdata.Solution{
							{
								Description: "Fix it",
							},
						},
						SeeAlso: "https://bitbucket.org/asecurityteam/custom-scanner-checks/src/main/checks/apache-detect.yaml",
					},
				},
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mocknuclei := NewMockNucleiInterface(ctrl)
			mockLogger := commonmocks.NewMockLogger(ctrl)
			mockStatFn := commonmocks.NewMockXStater(ctrl)

			scanner := Scanner{
				Nuclei: mocknuclei,
				StatFn: func(ctx context.Context) runhttp.Stat { return mockStatFn },
				LogFn:  func(context.Context) logevent.Logger { return mockLogger },
			}

			tt.Mocks(mocknuclei, mockStatFn, mockLogger)

			scanJob := ScanRecord{
				Resource:   "31.3.96.40",
				ID:         "jobID",
				TemplateID: "apache-detect",
			}
			template := string(string(tt.Data))
			scanJobs, err := scanner.Scan(ctx, []ScanRecord{scanJob}, []string{template})

			if len(scanJobs) > 0 {
				assert.Equal(t, 1, len(scanJobs))

				vulnReportResult := scanJobs[0].VulnReport
				vulnReportResult.Scan.StartTime = nil

				assert.IsType(t, tt.ExpectedError, err)
				assert.Equal(t, tt.ExpectedReturn, *vulnReportResult)
			}
		})
	}
}

func TestToVulnReportFailure(t *testing.T) {

	// this test is for template misses; mocknuclei.EXPECT().RunScan should only ever return []*output.InternalWrappedEvent

	scanType := vulnreportdata.SCAN_TYPE_NETWORK
	scanSourceNameCustom := vulnreportdata.SCAN_SOURCE_NAME_CUSTOM

	tc := []struct {
		Name           string
		Resource       string
		Err            string
		Data           []byte
		Mocks          func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger)
		ExpectedError  error
		ExpectedReturn vulnreportdata.VulnReport
	}{
		{
			Name:     "Golden Path To Vuln Report Failure - Hostname",
			Resource: "localhost",
			Err:      "somethingbroke",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"localhost"}, gomock.Any()).Return(nil, []*output.InternalWrappedEvent{{InternalEvent: output.InternalEvent{"Hostname": "localhost", "template-id": "apache-detect", "date": "Mon, 02 Jan 2006 15:04:05 MST"}}}, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.miss", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "localhost_apache-detect",
					IPAddresses:    nil,
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "hostErrors": "somethingbroke", "customScannerTemplate": "apache-detect"},
				},
			},
		},
		{
			Name:     "Golden Path To Vuln Report Failure - ip",
			Resource: "10.9.8.7",
			Err:      "somethingbroke",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"10.9.8.7"}, gomock.Any()).Return(nil, []*output.InternalWrappedEvent{{InternalEvent: output.InternalEvent{"ip": "10.9.8.7", "template-id": "apache-detect", "date": "Mon, 02 Jan 2006 15:04:05 MST"}}}, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.miss", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "10.9.8.7_apache-detect",
					Hostnames:      nil,
					IPAddresses:    []string{"10.9.8.7"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "hostErrors": "somethingbroke", "customScannerTemplate": "apache-detect"},
				},
			},
		},
		{
			Name:     "InternalEvent is nil",
			Resource: "localhost",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"localhost"}, gomock.Any()).Return(nil, []*output.InternalWrappedEvent{{InternalEvent: output.InternalEvent{"Hostname": "localhost", "template-id": "apache-detect", "date": "Mon, 02 Jan 2006 15:04:05 MST"}}}, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.miss", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "localhost_apache-detect",
					IPAddresses:    nil,
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "hostErrors": "", "customScannerTemplate": "apache-detect"},
				},
			},
		},
		{
			Name:     "To Vuln Report Failure - Missing date",
			Resource: "localhost",
			Err:      "somethingbroke",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"localhost"}, gomock.Any()).Return(nil, []*output.InternalWrappedEvent{{InternalEvent: output.InternalEvent{"Hostname": "localhost", "template-id": "apache-detect"}}}, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.miss", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "localhost_apache-detect",
					IPAddresses:    nil,
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "hostErrors": "somethingbroke", "alteredStartTime": "StartTime was altered due to missing date in Nuclei response", "customScannerTemplate": "apache-detect"},
				},
			},
		},
		{
			Name:     "To Vuln Report Failure - Unparseable date",
			Resource: "localhost",
			Err:      "somethingbroke",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater, mockLogger *commonmocks.MockLogger) {
				mocknuclei.EXPECT().RunScan([]string{"localhost"}, gomock.Any()).Return(nil, []*output.InternalWrappedEvent{{InternalEvent: output.InternalEvent{"Hostname": "localhost", "template-id": "apache-detect", "date": time.Now().String()}}}, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.miss", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "localhost_apache-detect",
					IPAddresses:    nil,
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"whoRequestedScan": "", "hostErrors": "somethingbroke", "alteredStartTime": "StartTime was altered due to unparseable date", "customScannerTemplate": "apache-detect"},
				},
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mocknuclei := NewMockNucleiInterface(ctrl)
			mockLogger := commonmocks.NewMockLogger(ctrl)
			mockStatFn := commonmocks.NewMockXStater(ctrl)

			hostErrors := sync.Map{}
			hostErrors.Store(tt.Resource, tt.Err)

			cache := &Cache{hostErrors: &hostErrors}

			scanner := Scanner{
				Nuclei:          mocknuclei,
				StatFn:          func(ctx context.Context) runhttp.Stat { return mockStatFn },
				LogFn:           func(context.Context) logevent.Logger { return mockLogger },
				hostErrorsCache: cache,
			}

			tt.Mocks(mocknuclei, mockStatFn, mockLogger)

			scanJob := ScanRecord{
				Resource:   tt.Resource,
				ID:         "jobID",
				TemplateID: "apache-detect",
			}
			template := string(string(tt.Data))
			scanJobs, err := scanner.Scan(ctx, []ScanRecord{scanJob}, []string{template})

			assert.IsType(t, tt.ExpectedError, err)

			if err == nil {
				assert.Equal(t, 1, len(scanJobs))

				vulnReportResult := scanJobs[0].VulnReport
				vulnReportResult.Scan.StartTime = nil

				assert.Equal(t, tt.ExpectedReturn, *vulnReportResult)
			}

		})
	}
}

func TestUnreachableHost(t *testing.T) {

	// this test is for unreachable URLs; mocknuclei.EXPECT().RunScan should only ever return nil, nil nil

	scanType := vulnreportdata.SCAN_TYPE_NETWORK
	scanSourceNameCustom := vulnreportdata.SCAN_SOURCE_NAME_CUSTOM

	tc := []struct {
		Name           string
		Data           []byte
		Mocks          func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater)
		ExpectedError  error
		ExpectedReturn vulnreportdata.VulnReport
	}{
		{
			Name: "Golden Path Unreachable Host",
			Data: []byte(
				`
id: apache-detect
info:
  name: "Bitbucket Server: Path Travarsal via Migration Tool"
  author: atlassian
  description: |
    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.
  tags: Bitbucket,Web,Community
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2019-3397
    cwe-id: CWE-22
  remediation: Fix it
` + RequestString),
			Mocks: func(mocknuclei *MockNucleiInterface, mockStatFn *commonmocks.MockXStater) {
				mocknuclei.EXPECT().RunScan([]string{"localhost"}, gomock.Any()).Return(nil, nil, nil)
				mockStatFn.EXPECT().Count("customscanner.vuln.unreachable", float64(1))
			},
			ExpectedError: nil,
			ExpectedReturn: vulnreportdata.VulnReport{
				ID: "jobID",
				Scan: vulnreportdata.Scan{
					Type: &scanType,
					Source: &vulnreportdata.Source{
						Name: &scanSourceNameCustom,
						ID:   "jobID",
					},
					StartTime: nil,
				},
				Asset: vulnreportdata.Asset{
					ScannerAssetID: "localhost_apache-detect",
					IPAddresses:    nil,
					Hostnames:      []string{"localhost"},
					Metadata:       map[string]interface{}{"reachable": false, "customScannerTemplate": "apache-detect"},
				},
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mocknuclei := NewMockNucleiInterface(ctrl)
			mockLogger := commonmocks.NewMockLogger(ctrl)
			mockStatFn := commonmocks.NewMockXStater(ctrl)

			scanner := Scanner{
				Nuclei: mocknuclei,
				StatFn: func(ctx context.Context) runhttp.Stat { return mockStatFn },
				LogFn:  func(context.Context) logevent.Logger { return mockLogger },
			}

			tt.Mocks(mocknuclei, mockStatFn)

			scanJob := ScanRecord{
				Resource:   "localhost",
				ID:         "jobID",
				TemplateID: "apache-detect",
			}
			template := string(string(tt.Data))
			scanJobs, err := scanner.Scan(ctx, []ScanRecord{scanJob}, []string{template})

			assert.Equal(t, 1, len(scanJobs))

			vulnReportResult := scanJobs[0].VulnReport
			vulnReportResult.Scan.StartTime = nil

			assert.IsType(t, tt.ExpectedError, err)
			assert.Equal(t, tt.ExpectedReturn, *vulnReportResult)

		})
	}
}

func TestGenerateScanSets(t *testing.T) {
	scanJobs := []ScanRecord{
		{
			Resource:   `a`,
			TemplateID: `1`,
		},
		{
			Resource:   `a`,
			TemplateID: `2`,
		},
		{
			Resource:   `a`,
			TemplateID: `3`,
		},
		{
			Resource:   `b`,
			TemplateID: `1`,
		},
		{
			Resource:   `b`,
			TemplateID: `2`,
		},
		{
			Resource:   `c`,
			TemplateID: `3`,
		},
		{
			Resource:   `d`,
			TemplateID: `1`,
		},
		{
			Resource:   `d`,
			TemplateID: `2`,
		},
		{
			Resource:   `d`,
			TemplateID: `3`,
		},
	}
	scanSets := generateScanSets(scanJobs)
	scanSetsJSON, _ := json.Marshal(scanSets)
	assert.Equal(t, 3, len(scanSets), string(scanSetsJSON))
}

func TestGetScanJobIDForFailureEventPanicSafety(t *testing.T) {
	assert.NotPanics(t, func() {
		_ = getScanJobIDForFailureEvent(nil, []ScanRecord{
			{
				Resource:   "host.name",
				TemplateID: "123",
			},
		})
	})
}

func TestToVulnReportFailureFailureEventPanicSafety(t *testing.T) {

	scanner := Scanner{}
	assert.NotPanics(t, func() {
		_, err := scanner.toVulnReportFailure(nil, "jobID")
		assert.IsType(t, err, err)

	})
}

// DO NOT DELETE; see README
// func TestUsefulForDebugging(t *testing.T) {

// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockStatFn := commonmocks.MockStatFn

// 	scanner := Scanner{
// 		Nuclei: &Nuclei{},
// 		StatFn: mockStatFn,
// 		Cache:  &Cache{},
// 	}

// 	template := "id: cmty-http-atlassian-bitbucket-path-traversal-migration-tool-rce\n\ninfo:\n  name: \"Bitbucket Server: Path Travarsal via Migration Tool\"\n  author: atlassian\n  description: |\n    Bitbucket Data Center had a path traversal vulnerability in the Data Center migration tool. A remote attacker with authenticated user with admin permissions can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Bitbucket Data Center. Bitbucket Server versions without a Data Center license are not vulnerable to this vulnerability.\n  tags: Bitbucket,Web,Community\n  classification:\n    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H\n    cvss-score: 9.1\n    cve-id: CVE-2019-3397\n    cwe-id: CWE-22\n\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/rest/applinks/1.0/manifest\"\n      # - \"{{BaseURL}}/bitbucket/rest/applinks/1.0/manifest\"\n\n    matchers-condition: and\n    matchers:\n      - type: status\n        status:\n          - 200\n\n      - type: regex\n        regex:\n          - '<typeId>bitbucket<\\/typeId>'\n        part: body\n\n      - type: regex\n        regex:\n          - '<version>(5\\.13\\.0|5\\.13\\.1|5\\.13\\.3|5\\.13\\.4|5\\.13\\.5|5\\.14\\.0|5\\.14\\.1|5\\.14\\.2|5\\.14\\.3|5\\.15\\.0|5\\.15\\.1|5\\.15\\.2|5\\.16\\.0|5\\.16\\.1|5\\.16\\.2|6\\.0\\.0|6\\.0\\.1|6\\.0\\.2|6\\.1\\.0|6\\.1\\.1)<\\/version>'\n        part: body\n"
// 	// address := "localhost:8081"
// 	// address := "10.9.8.7"

// 	address := "jira.stg.internal.atlassian.com"
// 	start := time.Now()
// 	scanJobs := []ScanRecord{{ID: "jid", Resource: address, TemplateID: "cmty-http-atlassian-bitbucket-path-traversal-migration-tool-rce"}}
// 	scanJobs, err := scanner.Scan(context.Background(), scanJobs, []string{string(template)})
// 	duration := time.Since(start)
// 	fmt.Printf("duration: %s", duration)
// 	assert.Nil(t, err)
// 	assert.Equal(t, address, scanJobs[0].VulnReport.Asset.Hostnames[0])
// 	if len(scanJobs[0].VulnReport.Vulns) > 0 {
// 		assert.Equal(t, `cve-2019-3397`, scanJobs[0].VulnReport.Vulns[0].CVEs[0].ID)
// 	}

// 	vrBytes, err := json.Marshal(scanJobs[0].VulnReport)
// 	assert.Nil(t, err)
// 	fmt.Printf("VULNREPORT: %s\n", string(vrBytes))
// 	// assert.True(t, false) // uncomment so go test prints fmt.Print* output to stdout
// }
