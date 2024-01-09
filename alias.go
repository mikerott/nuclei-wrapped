package main

import (
	"github.com/asecurityteam/runhttp"
)

// Logger is the project logger interface.
type Logger = runhttp.Logger

// LogFn is the recommended way to extract a logger from the context.
type LogFn = runhttp.LogFn

// LoggerFromContext is a concrete implementation of the LogFn interface.
var LoggerFromContext LogFn = runhttp.LoggerFromContext

// Stat is the project metrics client interface.
type Stat = runhttp.Stat

// StatFn is the recommended way to extract a metrics client from the context.
type StatFn = runhttp.StatFn

// StatFromContext is a concrete implementation of the StatFn interface.
var StatFromContext StatFn = runhttp.StatFromContext
