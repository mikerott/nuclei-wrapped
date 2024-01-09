package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheckMarkFailed(t *testing.T) {

	cache := New(3, DefaultMaxHostsCount)
	cache.hostErrors = &sync.Map{}

	cache.MarkFailed("http://example.com:80", fmt.Errorf("no address found for host"))
	if value, err := cache.failedTargets.Get("http://example.com:80"); err == nil && value != nil {
		require.Equal(t, 1, value, "could not get correct number of marked failed hosts")
	}
	cache.MarkFailed("example.com:80", fmt.Errorf("Client.Timeout exceeded while awaiting headers"))
	if value, err := cache.failedTargets.Get("example.com:80"); err == nil && value != nil {
		require.Equal(t, 2, value, "could not get correct number of marked failed hosts")
	}
	cache.MarkFailed("example.com", fmt.Errorf("could not resolve host"))
	if value, err := cache.failedTargets.Get("example.com"); err == nil && value != nil {
		require.Equal(t, 1, value, "could not get correct number of marked failed hosts")
	}
	for i := 0; i < 3; i++ {
		cache.MarkFailed("test", fmt.Errorf("could not resolve host"))
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}

func TestCache_GetHostErrors(t *testing.T) {

	tests := []struct {
		name string
		host string
		err  string
		want string
	}{
		{
			name: "hostErrors contains item - noAddr",
			host: "localhost",
			err:  noAddr,
			want: "no address found for host",
		},
		{
			name: "hostErrors contains item - timeOut",
			host: "localhost",
			err:  timeOut,
			want: "timeout exceeded while awaiting headers",
		},
		{
			name: "hostErrors contains item - noResolve",
			host: "localhost",
			err:  noResolve,
			want: "could not resolve host",
		},
		{
			name: "hostErrors contains item - undefined",
			host: "localhost",
			err:  "somethingweird",
			want: "somethingweird",
		},
		{
			name: "hostErrors contains no items",
			host: "localhost",
			err:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			hostErrors := sync.Map{}
			hostErrors.Store(tt.host, tt.err)

			c := &Cache{
				hostErrors: &hostErrors,
			}
			if got := c.GetHostErrors(tt.host); got != tt.want {
				t.Errorf("Cache.GetHostErrors() = %v, want %v", got, tt.want)
			}
		})
	}
}
