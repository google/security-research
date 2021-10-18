package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/fatih/color"
	"github.com/google/go-tpm/tpm2"
	"github.com/mitchellh/go-wordwrap"

	"github.com/google/security-research/pocs/bios/tpm-carte-blanche/lib/open"
)

// ResultCode represents the result of some TPM bug test, at a high level.
type ResultCode int

const (
	// OK indicates that the test revealed no problems.
	OK ResultCode = iota
	// Warn indicates that the test revealed a possible problem.
	Warn
	// Vuln indicates that the test revealed a problem.
	Vuln
	// Error indicates that the test had some execution problem.
	Error
)

func (rc ResultCode) String() string {
	switch rc {
	case OK:
		return "OK"
	case Warn:
		return "WARN"
	case Vuln:
		return "VULN"
	case Error:
		return "ERROR"
	}
	return fmt.Sprintf("unknown code (%d)", rc)
}

// Result represents the result of some TPM bug test, with details.
type Result struct {
	// Code contains the high-level result code from the test.
	Code ResultCode
	// Details contains an informative string about what the test found.
	Details string
}

// Test is a single TPM bug test.
type Test func(tpm io.ReadWriter) Result

var tests = map[string]Test{
	"empty-low-pcr":      emptyLowPCR,
	"null-platform-auth": nullPlatformAuth,
	"null-lockout-auth":  nullLockoutAuth,
}

var (
	tpmPath  = flag.String("tpm", "", "path to the tpm (Linux only)")
	testName = flag.String("test", "", "name of a test to run")
)

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: bugtool [ --test=<test> ] [ --tpm=<path> ]\n\n")
	fmt.Fprintf(w, "<path> is the path to the TPM (default /dev/tpm0):\n")
	fmt.Fprintf(w, "<test> may be one of (default: run all the tests):\n")
	for test, _ := range tests {
		fmt.Fprintf(w, "        %s\n", test)
	}
}

func main() {
	os.Exit(mainWithExit())
}

type testResult struct {
	test   string
	result Result
}

func mainWithExit() int {
	tpm, err := open.TPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open TPM at '%s': %v\n", *tpmPath, err)
		return -1
	}
	defer tpm.Close()

	var results []testResult

	if *testName != "" {
		test, ok := tests[*testName]
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown test '%s'\n", *testName)
			printUsage(os.Stderr)
			return -1
		}
		results = append(results, testResult{*testName, test(tpm)})
	} else {
		for testName, test := range tests {
			results = append(results, testResult{testName, test(tpm)})
		}
	}

	failed := false
	for _, result := range results {
		printResult(result)
		if result.result.Code != OK {
			failed = true
		}
	}
	if failed {
		return -1
	}
	return 0
}

func printResult(tr testResult) {
	resultColor := colorForCode(tr.result.Code)
	messageColor := colorForMessage(tr.result.Code)
	resultColor.Printf("[ %s ]: %s", tr.test, tr.result.Code)
	messageColor.Print("\n")
	messageColor.Print(wordwrap.WrapString(tr.result.Details, 80))
	messageColor.Print("\n")
}

func colorForCode(rc ResultCode) *color.Color {
	switch rc {
	case Warn:
		return color.New(color.FgYellow)
	case Vuln:
		return color.New(color.FgRed)
	case Error:
		return color.New(color.FgBlack, color.BgYellow)
	}
	return color.New(color.FgWhite, color.Bold)
}

func colorForMessage(rc ResultCode) *color.Color {
	switch rc {
	case Vuln, Error:
		return color.New(color.FgMagenta)
	case Warn:
		return color.New(color.FgYellow)
	}
	return color.New(color.FgWhite)
}

func isHashError(err error) bool {
	var pErr tpm2.ParameterError
	if errors.As(err, &pErr) && pErr.Code == tpm2.RCHash {
		return true
	}
	// Windows does some error translation where the error is a HandleError
	var hErr tpm2.HandleError
	if errors.As(err, &hErr) && hErr.Code == tpm2.RCHash {
		return true
	}
	return false
}

func emptyLowPCR(tpm io.ReadWriter) Result {
	algs := []tpm2.Algorithm{
		tpm2.AlgSHA1,
		tpm2.AlgSHA256,
		tpm2.AlgSHA384,
		tpm2.AlgSHA512,
		tpm2.AlgSHA3_256,
		tpm2.AlgSHA3_384,
		tpm2.AlgSHA3_512,
	}
	var badAlgs []tpm2.Algorithm

	for _, alg := range algs {
		sel := tpm2.PCRSelection{
			Hash: alg,
			PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7},
		}
		pcrs, err := tpm2.ReadPCRs(tpm, sel)
		if err != nil {
			if !isHashError(err) {
				return Result{
					Code:    Error,
					Details: fmt.Sprintf("calling tpm2.ReadPCRs: %s\n%+v", err.Error(), reflect.TypeOf(err)),
				}
			}
			continue
		}
		// The TPM may return RC_SUCCESS and an empty PCR list if the PCR bank is disabled.
		if len(pcrs) == 0 {
			continue
		}
		allZeros := true
		for i := range pcrs {
			for j := range pcrs[i] {
				if pcrs[i][j] != 0 {
					allZeros = false
				}
			}
		}
		if allZeros {
			badAlgs = append(badAlgs, alg)
		}
	}

	if len(badAlgs) != 0 {
		return Result{
			Code:    Vuln,
			Details: fmt.Sprintf("The following banks have all zeroes in PCR[0-7]: %s", badAlgs),
		}
	}
	return Result{OK, ""}
}

type tpmProperties uint32

const (
	ownerAuthSet       tpmProperties = 1 << 0
	endorsementAuthSet tpmProperties = 1 << 1
	lockoutAuthSet     tpmProperties = 1 << 2
	disableClear       tpmProperties = 1 << 8
	inLockout          tpmProperties = 1 << 9
	tpmGeneratedEps    tpmProperties = 1 << 10
)

func getTpmProperties(tpm io.ReadWriter) (tpmProperties, error) {
	props, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.TPMAPermanent))
	if err != nil {
		return 0, err
	}
	if len(props) != 1 {
		return 0, fmt.Errorf("got %d properties", len(props))
	}
	if prop, ok := props[0].(tpm2.TaggedProperty); !ok || prop.Tag != tpm2.TPMAPermanent {
		return 0, fmt.Errorf("got wrong property: %v", props[0])
	} else {
		return tpmProperties(prop.Value), nil
	}
}

func nullPlatformAuth(tpm io.ReadWriter) Result {
	sessHandle, _, err := tpm2.StartAuthSession(tpm, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return Result{Error, err.Error()}
	}
	defer tpm2.FlushContext(tpm, sessHandle)

	ac := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, err := tpm2.PolicySecret(tpm, tpm2.HandlePlatform, ac, sessHandle, nil, nil, nil, 0); err != nil {
		return Result{OK, ""}
	}
	return Result{Vuln, "platform auth is null"}
}

func nullLockoutAuth(tpm io.ReadWriter) Result {
	props, err := getTpmProperties(tpm)
	if err != nil {
		return Result{Error, err.Error()}
	}
	if props&lockoutAuthSet == 0 {
		return Result{Vuln, "lockout auth not set"}
	}
	return Result{OK, ""}
}
