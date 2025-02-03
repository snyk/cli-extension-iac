package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/hcl_interpreter"
	"github.com/snyk/policy-engine/pkg/input"
)

// ErrorCode represents one of the possible known error conditions that might
// occur when running the engine.
type ErrorCode int

const (
	ErrorCodeNoLoadableInputs ErrorCode = iota
	ErrorCodeUnableToRecognizeInputType
	ErrorCodeUnsupportedInputType
	ErrorCodeUnableToResolveLocation
	ErrorCodeUnrecognizedFileExtension
	ErrorCodeFailedToParseInput
	ErrorCodeInvalidInput
	ErrorCodeUnableToReadFile
	ErrorCodeUnableToReadDir
	ErrorCodeUnableToReadStdin
	ErrorCodeFailedToLoadRegoAPI
	ErrorCodeFailedToLoadRules
	ErrorCodeFailedToCompile
	ErrorCodeUnableToReadPath
	ErrorCodeFailedToMakeResourcesResolvers
	ErrorCodeResourcesResolverError
	ErrorCodeSubmoduleLoadingError
	ErrorCodeMissingRemoteSubmodulesError
	ErrorCodeEvaluationError
	ErrorCodeMissingTermError
)

// Error represents a known error condition that might occur when running the
// engine. It contains a message, for debugging purposes, and additional
// information (like a path) when possible.
type Error struct {
	Message string
	Code    ErrorCode
	Path    string
}

func (e Error) Error() string {
	var b strings.Builder

	fmt.Fprintf(&b, "engine error %d: %s", e.Code, e.Message)

	if e.Path != "" {
		fmt.Fprintf(&b, ": %s", e.Path)
	}

	return b.String()
}

type SubmoduleLoadingError struct {
	Message string
	Code    ErrorCode
	Path    string
	Module  string
}

func (e SubmoduleLoadingError) Error() string {
	return e.Message
}

type MissingRemoteSubmodulesError struct {
	Message        string
	Code           ErrorCode
	Path           string
	Dir            string
	MissingModules []string
}

func (e MissingRemoteSubmodulesError) Error() string {
	return e.Message
}

type EvaluationError struct {
	Message     string
	Code        ErrorCode
	Path        string
	Expressions []string
}

func (e EvaluationError) Error() string {
	return e.Message
}

type MissingTermError struct {
	Message string
	Code    ErrorCode
	Path    string
	Term    string
}

func (e MissingTermError) Error() string {
	return e.Message
}

func unwrapEngineError(err error, path string) error {
	if shouldIgnoreError(err) {
		return nil
	}

	if errorCode, unwrapped := errorCode(err); unwrapped != nil {
		return Error{
			Message: unwrapped.Error(),
			Code:    errorCode,
			Path:    path,
		}
	}

	return err
}

func errorCode(err error) (ErrorCode, error) {
	switch {
	case errors.Is(err, input.UnsupportedInputType):
		return ErrorCodeUnsupportedInputType, err
	case errors.Is(err, input.UnableToResolveLocation):
		return ErrorCodeUnableToResolveLocation, err
	case errors.Is(err, input.UnrecognizedFileExtension):
		return ErrorCodeUnrecognizedFileExtension, err
	case errors.Is(err, input.FailedToParseInput):
		return ErrorCodeFailedToParseInput, err
	case errors.Is(err, input.UnableToReadFile):
		return ErrorCodeUnableToReadFile, err
	case errors.Is(err, input.UnableToReadDir):
		return ErrorCodeUnableToReadDir, err
	case errors.Is(err, engine.FailedToLoadRegoAPI):
		return ErrorCodeFailedToLoadRegoAPI, err
	case errors.Is(err, engine.FailedToLoadRules):
		return ErrorCodeFailedToLoadRules, err
	case errors.Is(err, engine.FailedToCompile):
		return ErrorCodeFailedToCompile, err
	default:
		return 0, nil
	}
}

func shouldIgnoreError(err error) bool {
	switch {
	case errors.Is(err, input.InvalidInput):
		return true
	default:
		return false
	}
}

func unwrapEngineWarning(err error, path string) error {
	var submoduleLoadingError hcl_interpreter.SubmoduleLoadingError
	var missingRemoteSubmodulesError hcl_interpreter.MissingRemoteSubmodulesError
	var evaluationError hcl_interpreter.EvaluationError
	var missingTermError hcl_interpreter.MissingTermError

	switch {
	case errors.As(err, &submoduleLoadingError):
		return SubmoduleLoadingError{
			Message: err.Error(),
			Code:    ErrorCodeSubmoduleLoadingError,
			Path:    path,
			Module:  submoduleLoadingError.Module,
		}
	case errors.As(err, &missingRemoteSubmodulesError):
		return MissingRemoteSubmodulesError{
			Message:        err.Error(),
			Code:           ErrorCodeMissingRemoteSubmodulesError,
			Path:           path,
			Dir:            missingRemoteSubmodulesError.Dir,
			MissingModules: missingRemoteSubmodulesError.MissingModules,
		}
	case errors.As(err, &evaluationError):
		var expressions []string

		for _, diag := range evaluationError.Diags {
			expr := fmt.Sprintf("%s: %s", diag.Subject, diag.Summary)
			expressions = append(expressions, expr)
		}

		return EvaluationError{
			Message:     err.Error(),
			Code:        ErrorCodeEvaluationError,
			Path:        path,
			Expressions: expressions,
		}
	case errors.As(err, &missingTermError):
		return MissingTermError{
			Message: err.Error(),
			Code:    ErrorCodeMissingTermError,
			Path:    path,
			Term:    missingTermError.Term,
		}
	default:
		return nil
	}
}
