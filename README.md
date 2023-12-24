# nuclei-wrapped
A repo to demonstrated possible ways to wrap nuclei SDK

## Working as Expected

```
go mod vendor
go test
```

Observe success!

## Unexpected Behavior

* Change the `      - "{{BaseURL}}/"` line in `nuclei_test.go` to `      - "{{BaseURL}}/will-return-404"`
* Change the expected results from 1 and 0 to 0 and 1, respectively, on lines 54 and 55 in `nuclei_test.go`

Why does it fail?  I expected Nuclei to be able to reach `https://google.com/will-return-404` and call my
`writer.WriteFailure` func (see `writer.go`).

What have I done wrong?  What is misconfigured in `nuclei.go`?

Using Nuclei as embedded SDK is... difficult.  There are init functions that must be called, or interfaces
the SDK user must implement.  These are not documented well [here](https://github.com/projectdiscovery/nuclei/blob/main/DESIGN.md) and I could not find a comprehensive
example.  I use the debugger a **lot** to figure out what pointer I failed to initialize deep in Nuclei SDK.
