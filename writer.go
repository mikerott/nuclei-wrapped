package main

import (
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// writer is an implementation of output.Writer
type writer struct {
	resultEvents  []*output.ResultEvent
	failureEvents []*output.InternalWrappedEvent
	mutex         sync.RWMutex
}

// Close closes the output writer interface
func (w *writer) Close() {}

// Colorizer returns the colorizer instance for writer
func (w *writer) Colorizer() aurora.Aurora {
	return aurora.NewAurora(false)
}

// Write writes the event to file and/or screen.
func (w *writer) Write(event *output.ResultEvent) error {
	w.mutex.Lock()
	if w.resultEvents == nil {
		w.resultEvents = []*output.ResultEvent{}
	}
	w.resultEvents = append(w.resultEvents, event)
	w.mutex.Unlock()
	return nil
}

// WriteFailure writes the optional failure event for template to file and/or screen.
func (w *writer) WriteFailure(event *output.InternalWrappedEvent) error {
	w.mutex.Lock()
	if w.failureEvents == nil {
		w.failureEvents = []*output.InternalWrappedEvent{}
	}
	w.failureEvents = append(w.failureEvents, event)
	w.mutex.Unlock()
	return nil
}

// Request logs a request in the trace log
func (w *writer) Request(templateID, url, requestType string, err error) {}

func (w *writer) GetFailures() []*output.InternalWrappedEvent {
	return w.failureEvents
}

func (w *writer) GetResults() []*output.ResultEvent {
	return w.resultEvents
}

func (w *writer) WriteStoreDebugData(host, templateID, eventType string, data string) {}
