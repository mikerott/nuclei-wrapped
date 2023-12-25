package main

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestUsefulForDebuggingHit(t *testing.T) {

	templateString := `
id: my-template

info:
  name: "My Test Template"
  author: mikerott
  description: |
    This is a test template.
  tags: mike
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 5.0
    cve-id: CVE-2019-0000
    cwe-id: CWE-22

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
`

	address := "google.com"

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan([]string{address}, template)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(resultEvents))
	assert.Equal(t, 0, len(failureEvents))

}

func TestUsefulForDebuggingMiss(t *testing.T) {

	templateString := `
id: my-template

info:
  name: "My Test Template"
  author: mikerott
  description: |
    This is a test template.
  tags: mike
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 5.0
    cve-id: CVE-2019-0000
    cwe-id: CWE-22

http:
  - method: GET
    path:
      - "{{BaseURL}}/this-is-a-404"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
`

	address := "google.com"

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan([]string{address}, template)

	assert.Nil(t, err)
	assert.Equal(t, 0, len(resultEvents))
	assert.Equal(t, 1, len(failureEvents))

}
