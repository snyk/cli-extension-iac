package engine

import (
	"context"
	"io"

	"github.com/rs/zerolog"
	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/spf13/afero"
)

type Results = models.Results
type MetadataResult = engine.MetadataResult

// Engine scans a set of paths, identifies IaC files, and reports any found
// vulnerability.
type Engine struct {
	wrapped *engine.Engine
	logger  *zerolog.Logger
}

type EngineOptions struct {
	SnykBundle        io.ReadCloser
	CustomRuleBundles []bundle.Reader
	Logger            *zerolog.Logger
}

func NewEngine(ctx context.Context, options EngineOptions) *Engine {
	var providers []data.Provider

	if options.SnykBundle != nil {
		providers = append(providers, data.TarGzProvider(options.SnykBundle))
	}

	wrapped := engine.NewEngine(ctx, &engine.EngineOptions{
		Providers:     providers,
		BundleReaders: options.CustomRuleBundles,
		// policy engine logger was never provided in the original snyk-iac-test
		// it could be added if needed, but it is very noisy
	})

	engine := Engine{
		wrapped: wrapped,
		logger:  options.Logger,
	}

	return &engine
}

type RunOptions struct {
	FS                afero.Fs
	Paths             []string
	RuleIDs           []string
	Scan              string
	VarFile           string
	DetectionDepth    int
	ResourcesResolver policy.ResourcesResolver
}

// Run runs the engine according to its configuration, and returns the results
// of the scan. If one or more errors occurred during the execution of the
// engine, Run returns them. In an error condition is known, it is encapsulated
// by an Error; otherwise, Run returns a generic error.
func (e *Engine) Run(ctx context.Context, options RunOptions) (*Results, []error) {
	loader, errors, _ := e.LoadInput(options)

	inputs := loader.ToStates()
	if len(inputs) == 0 {
		return nil, errors
	}

	results := e.Eval(ctx, options, inputs)

	return e.PostProcess(results, loader, options), errors
}

func (e *Engine) LoadInput(options RunOptions) (input.Loader, []error, []error) {
	scanner := scanner{
		fs:             options.FS,
		detectionDepth: options.DetectionDepth,
		varFile:        options.VarFile,
		logger:         e.logger,
	}

	loader, errors, warnings := scanner.scan(options.Paths)
	return loader, errors, warnings
}

func (e *Engine) Eval(ctx context.Context, options RunOptions, inputs []models.State) *Results {
	return e.wrapped.Eval(ctx, &engine.EvalOptions{
		Inputs:            inputs,
		ResourcesResolver: options.ResourcesResolver,
		RuleIDs:           options.RuleIDs,
	})
}

func (e *Engine) PostProcess(results *Results, loader input.Loader, options RunOptions) *Results {
	annotate(results, loader)
	filter(results, options)
	return results
}

// Metadata returns the metadata of all Policies that have been loaded into this
// Engine instance.
func (e *Engine) Metadata(ctx context.Context) ([]MetadataResult, error) {
	return e.wrapped.Metadata(ctx)
}

func (e *Engine) InitializationErrors() []error {
	var errs []error
	for _, err := range e.wrapped.InitializationErrors {
		errs = append(errs, unwrapEngineError(err, ""))
	}
	return errs
}
