package engine

import engine "github.com/snyk/cli-extension-iac/internal/policyengine"

type ErrorCode = engine.ErrorCode

const (
	ErrorCodeNoLoadableInputs               = engine.ErrorCodeNoLoadableInputs
	ErrorCodeUnableToRecognizeInputType     = engine.ErrorCodeUnableToRecognizeInputType
	ErrorCodeUnsupportedInputType           = engine.ErrorCodeUnsupportedInputType
	ErrorCodeUnableToResolveLocation        = engine.ErrorCodeUnableToResolveLocation
	ErrorCodeUnrecognizedFileExtension      = engine.ErrorCodeUnrecognizedFileExtension
	ErrorCodeFailedToParseInput             = engine.ErrorCodeFailedToParseInput
	ErrorCodeInvalidInput                   = engine.ErrorCodeInvalidInput
	ErrorCodeUnableToReadFile               = engine.ErrorCodeUnableToReadFile
	ErrorCodeUnableToReadDir                = engine.ErrorCodeUnableToReadDir
	ErrorCodeUnableToReadStdin              = engine.ErrorCodeUnableToReadStdin
	ErrorCodeFailedToLoadRegoAPI            = engine.ErrorCodeFailedToLoadRegoAPI
	ErrorCodeFailedToLoadRules              = engine.ErrorCodeFailedToLoadRules
	ErrorCodeFailedToCompile                = engine.ErrorCodeFailedToCompile
	ErrorCodeUnableToReadPath               = engine.ErrorCodeUnableToReadPath
	ErrorCodeFailedToMakeResourcesResolvers = engine.ErrorCodeFailedToMakeResourcesResolvers
	ErrorCodeResourcesResolverError         = engine.ErrorCodeResourcesResolverError
	ErrorCodeSubmoduleLoadingError          = engine.ErrorCodeSubmoduleLoadingError
	ErrorCodeMissingRemoteSubmodulesError   = engine.ErrorCodeMissingRemoteSubmodulesError
	ErrorCodeEvaluationError                = engine.ErrorCodeEvaluationError
	ErrorCodeMissingTermError               = engine.ErrorCodeMissingTermError
)

type Error = engine.Error
type SubmoduleLoadingError = engine.SubmoduleLoadingError
type MissingRemoteSubmodulesError = engine.MissingRemoteSubmodulesError
type EvaluationError = engine.EvaluationError
type MissingTermError = engine.MissingTermError
