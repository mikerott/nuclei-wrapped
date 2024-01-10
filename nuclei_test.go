package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

const (
	templateString = `
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
)

func TestTemplateHit(t *testing.T) {

	addresses := []string{"http://localhost"} // template hit = resultEvent

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan(addresses, template)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(resultEvents))
	assert.Equal(t, 0, len(failureEvents))

}

func TestTemplateMiss(t *testing.T) {

	address := "http://localhost/this-is-a-501" // template miss = failureEvent

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan([]string{address}, template)

	assert.Nil(t, err)
	assert.Equal(t, 0, len(resultEvents))
	assert.Equal(t, 1, len(failureEvents))

	_, ok := (failureEvents[0].InternalEvent)["error"]

	assert.False(t, ok) // no "error" in the map
	assert.Equal(t, (failureEvents[0].InternalEvent)["status_code"], 501)

}

func TestUnreachableConnectionRefused(t *testing.T) {

	address := "http://localhost:9999" // unreachable = failureEvent

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan([]string{address}, template)

	assert.Nil(t, err)
	assert.Equal(t, 0, len(resultEvents))
	assert.Equal(t, 1, len(failureEvents))

	assert.True(t, len((failureEvents[0].InternalEvent)["error"].(string)) > 0)
	assert.Equal(t, (failureEvents[0].InternalEvent)["status_code"], 0)
	assert.True(t, strings.Contains((failureEvents[0].InternalEvent)["error"].(string), "connection refused"))

}

func TestUnreachableTimedOut(t *testing.T) {

	httpClient := http.Client{}
	request, err := http.NewRequest("POST", "http://localhost/instruct", strings.NewReader(`{"matchers":{"path":"/latency5000","method":"get"},"behaviors":{"latency":5000},"response":{"code":200}}`))
	request.Header.Add("Content-Type", "application/json")
	assert.Nil(t, err)
	response, err := httpClient.Do(request)
	assert.Nil(t, err, "Did you run from `make test`, because you should have!")
	assert.Equal(t, 201, response.StatusCode)

	address := "http://localhost/latency5000" // will time out

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan([]string{address}, template)

	assert.Nil(t, err)
	assert.Equal(t, 0, len(resultEvents))
	assert.Equal(t, 1, len(failureEvents))

	assert.True(t, len((failureEvents[0].InternalEvent)["error"].(string)) > 0)
	assert.Equal(t, (failureEvents[0].InternalEvent)["status_code"], 0)
	assert.True(t, strings.Contains((failureEvents[0].InternalEvent)["error"].(string), "context deadline exceeded"))

}

func TestMultipleAddresses(t *testing.T) {

	addresses := []string{
		"http://localhost",               // hit = resultEvent
		"http://localhost/this-is-a-501", // template miss = failureEvent
		"http://localhost:9999",          // unreachable = failureEvent
	}

	nuclei := Nuclei{}

	template := templates.Template{}
	if err := yaml.Unmarshal([]byte(templateString), &template); err != nil {
		assert.FailNow(t, err.Error())
	}

	resultEvents, failureEvents, err := nuclei.RunScan(addresses, template)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(resultEvents))
	assert.Equal(t, 2, len(failureEvents))

}
