package command

import (
	"github.com/snyk/cli-extension-iac/internal/engine"
)

// errorCode is a unique error code that is assigned to a user error.
type errorCode int

// scanError is an error that is reported to the caller. The type of a scanError
// is uniquely identified by its error code. A scanError contains a message to
// help with debugging, but userErrors with the same error code can contain
// different error messages. A scanError can contain free-form fields to
// transport some important information across the process boundary (e.g. the
// path of a file that cause the error).
//
// Note that tha scanError is not a Go error, but a concept defined by this
// domain. A scanError is a first-class citizen in the response returned to the
// user. In other words, a scanError represent an error condition that was
// handled and is not an unexpected outcome of the program.
type scanError struct {
	Message string         `json:"message"`
	Code    errorCode      `json:"code"`
	Fields  map[string]any `json:"fields,omitempty"`
}

const (
	errorCodeNoPaths errorCode = 2000 + iota
)

const (
	errorCodeCwdTraversal errorCode = 2003 + iota
	errorCodeOpenBundle
	errorCodeFetchCustomRuleBundles
)

const (
	errorCodeScan errorCode = 2100 + iota
	errorCodeUnableToRecognizeInputType
	errorCodeUnsupportedInputType
	errorCodeUnableToResolveLocation
	errorCodeUnrecognizedFileExtension
	errorCodeFailedToParseInput
	errorCodeInvalidInput
	errorCodeUnableToReadFile
	errorCodeUnableToReadDir
	errorCodeUnableToReadStdin
	errorCodeFailedToLoadRegoAPI
	errorCodeFailedToLoadRules
	errorCodeFailedToCompile
	errorCodeUnableToReadPath
	errorCodeNoLoadableInput
	errorCodeFailedToMakeResourcesResolvers
	errorCodeResourcesResolverError
	errorCodeTestLimitReached
	errorCodeUnableToTrackUsage
)

const (
	errorCodeProcessResults errorCode = 2200 + iota
	errorCodeEntitlementNotEnabled
	errorCodeReadSettings
)

// Warnings
const (
	errorCodeSubmoduleLoadingError = 3000 + iota
	errorCodeMissingRemoteSubmodulesError
	errorCodeEvaluationError
	errorCodeMissingTermError
)

var errNoPaths = scanError{
	Message: "no valid paths",
	Code:    errorCodeNoPaths,
}

var errOpenBundle = scanError{
	Message: "unable to open bundle",
	Code:    errorCodeOpenBundle,
}

var errFetchCustomRulesBundles = scanError{
	Message: "unable to fetch custom rule bundles",
	Code:    errorCodeFetchCustomRuleBundles,
}

var errScan = scanError{
	Message: "unable to scan",
	Code:    errorCodeScan,
}

var errProcessResults = scanError{
	Message: "unable to process the results",
	Code:    errorCodeProcessResults,
}

var errEntitlementInfrastructureAsCodeNotEnabled = scanError{
	Message: "entitlement 'infrastructureAsCode' is not enabled",
	Code:    errorCodeEntitlementNotEnabled,
	Fields: map[string]any{
		"entitlement": "infrastructureAsCode",
	},
}

var testLimitReached = scanError{
	Message: "test limit reached",
	Code:    errorCodeTestLimitReached,
}

var unableToTrackUsage = scanError{
	Message: "unable to track usage",
	Code:    errorCodeUnableToTrackUsage,
}

var errReadSettings = scanError{
	Message: "unable to read the IaC organization settings",
	Code:    errorCodeReadSettings,
}

func cwdTraversalError(path string) scanError {
	return newScanError("current working directory traversal", errorCodeCwdTraversal, map[string]any{"path": path})
}

func errorsToScanErrors(errors []error) []scanError {
	var result []scanError

	for _, err := range errors {
		result = append(result, errorToScanError(err))
	}

	return result
}

func errorToScanError(err error) scanError {
	if result, ok := err.(engine.Error); ok {
		fields := make(map[string]any)

		if result.Path != "" {
			fields["path"] = result.Path
		}

		switch result.Code {
		case engine.ErrorCodeUnableToReadFile:
			return newScanError("unable to read file", errorCodeUnableToReadFile, fields)
		case engine.ErrorCodeUnableToRecognizeInputType:
			return newScanError("unable to recognize input type", errorCodeUnableToRecognizeInputType, fields)
		case engine.ErrorCodeUnsupportedInputType:
			return newScanError("unsupported input type", errorCodeUnsupportedInputType, fields)
		case engine.ErrorCodeUnableToResolveLocation:
			return newScanError("unable to resolve location", errorCodeUnableToResolveLocation, fields)
		case engine.ErrorCodeUnrecognizedFileExtension:
			return newScanError("unrecognized file extension", errorCodeUnrecognizedFileExtension, fields)
		case engine.ErrorCodeFailedToParseInput:
			return newScanError("failed to parse input", errorCodeFailedToParseInput, fields)
		case engine.ErrorCodeInvalidInput:
			return newScanError("invalid input for input type", errorCodeInvalidInput, fields)
		case engine.ErrorCodeUnableToReadDir:
			return newScanError("unable to read directory", errorCodeUnableToReadDir, fields)
		case engine.ErrorCodeUnableToReadStdin:
			return newScanError("unable to read stdin", errorCodeUnableToReadStdin, fields)
		case engine.ErrorCodeFailedToLoadRegoAPI:
			return newScanError("failed to load the snyk Rego API", errorCodeFailedToLoadRegoAPI, fields)
		case engine.ErrorCodeFailedToLoadRules:
			return newScanError("failed to load rules", errorCodeFailedToLoadRules, fields)
		case engine.ErrorCodeFailedToCompile:
			return newScanError("failed to compile rules", errorCodeFailedToCompile, fields)
		case engine.ErrorCodeUnableToReadPath:
			return newScanError("unable to read path", errorCodeUnableToReadPath, fields)
		case engine.ErrorCodeNoLoadableInputs:
			return newScanError("no loadable input", errorCodeNoLoadableInput, fields)
		case engine.ErrorCodeFailedToMakeResourcesResolvers:
			return newScanError(result.Message, errorCodeFailedToMakeResourcesResolvers, fields)
		case engine.ErrorCodeResourcesResolverError:
			return newScanError(result.Message, errorCodeResourcesResolverError, fields)
		}
	}
	if result, ok := err.(engine.SubmoduleLoadingError); ok {
		return newScanError(result.Message, errorCodeSubmoduleLoadingError, map[string]any{"path": result.Path, "module": result.Module})
	}
	if result, ok := err.(engine.MissingRemoteSubmodulesError); ok {
		return newScanError(result.Message, errorCodeMissingRemoteSubmodulesError, map[string]any{"path": result.Path, "dir": result.Dir, "modules": result.MissingModules})
	}
	if result, ok := err.(engine.EvaluationError); ok {
		return newScanError(result.Message, errorCodeEvaluationError, map[string]any{"path": result.Path, "expressions": result.Expressions})
	}
	if result, ok := err.(engine.MissingTermError); ok {
		return newScanError(result.Message, errorCodeMissingTermError, map[string]any{"path": result.Path, "term": result.Term})
	}
	return errScan
}

func newScanError(msg string, code errorCode, fields map[string]any) scanError {
	return scanError{
		Message: msg,
		Code:    code,
		Fields:  fields,
	}
}
