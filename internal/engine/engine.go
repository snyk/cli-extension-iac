package engine

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/spf13/afero"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	resultspkg "github.com/snyk/cli-extension-iac/internal/results"
)

// Zerolog or the Policy Engine mess up with the default logger from the
// standard library, which is used in this program for debugging messages. The
// following lines restore the default flags and output.

func init() {
	log.Default().SetOutput(os.Stderr)
	log.Default().SetFlags(log.LstdFlags)
}

type Results = engine.Results

type Engine struct {
	FS afero.Fs
}

type RunOptions struct {
	Paths                []string
	SnykBundle           io.ReadCloser
	CustomRuleBundles    []bundle.Reader
	OrgPublicID          string
	SnykCloudEnvironment string
	SnykClient           cloudapi.Client
	Scan                 string
	DetectionDepth       int
	VarFile              string
}

func (e *Engine) Run(ctx context.Context, options RunOptions) (*Results, resultspkg.ScanAnalytics, []error, []error) {
	var errs []error

	resolver, resolverErrCh, err := newResourcesResolvers(ctx, options)
	if err != nil {
		return nil, resultspkg.ScanAnalytics{}, append(errs, Error{
			Message: fmt.Sprintf("An error occurred preparing cloud context: %s", err.Error()),
			Code:    ErrorCodeFailedToMakeResourcesResolvers,
		}), nil
	}

	wrapped := engine.NewEngine(ctx, engine.EngineOptions{
		SnykBundle:        options.SnykBundle,
		CustomRuleBundles: options.CustomRuleBundles,
	})
	// Initialization errors are considered non-fatal. The engine is able to
	// continue running bundles whichever bundles did successfully initialize.
	errs = append(errs, wrapped.InitializationErrors()...)

	runOptions := engine.RunOptions{
		FS:                e.FS,
		Paths:             options.Paths,
		Scan:              options.Scan,
		DetectionDepth:    options.DetectionDepth,
		VarFile:           options.VarFile,
		ResourcesResolver: resolver,
	}
	loader, configLoaderErrs, configLoaderWarnings := wrapped.LoadInput(runOptions)
	inputs := loader.ToStates()
	if len(inputs) == 0 {
		return nil, resultspkg.ScanAnalytics{}, append(errs, configLoaderErrs...), configLoaderWarnings
	}

	// Evaluate policies in another goroutine in case
	// awaitResultsAndGetSuppressions needs to run more evaluations, which it can
	// do concurrently.
	resultsCh := evalInBackground(wrapped, ctx, runOptions, inputs)
	evalResults, suppressedResults := awaitResultsAndGetSuppressions(wrapped, ctx, runOptions, inputs, resultsCh)

	results := wrapped.PostProcess(evalResults, loader, runOptions)

	// TODO: now that we've evaluated policies, we might have some policy
	// evaluation errors. These are in the ruleResults data structure, _not_ the
	// configLoaderErrs, and we should propagate them up to the CLI user instead
	// of discarding them as we do now, which effectively gives false negatives.
	//
	// This requires some UX thought, as currently all non-fatal errors are
	// grouped by file path, and we cannot associate policy evaluation errors with
	// file paths, because the policy failed without marking any resources as
	// relevant.
	//
	// Since cloud context errors from ResourcesResolvers depend on the user's
	// configuration of access controls, and on potentially-flaky API calls, we
	// are probably more likely to see errors from these policies than others.
	// Until we resolve the TODO above, we catch cloud context policy evaluation
	// errors in a side channel and bubble them up. Since these errors are not
	// path-scoped, they will be considered fatal, and any other results will be
	// discarded.
	select {
	case err := <-resolverErrCh:
		if err != nil {
			return nil, resultspkg.ScanAnalytics{}, append(errs, err), configLoaderWarnings
		}
	default:
	}

	return results, resultspkg.ScanAnalytics{SuppressedResults: suppressedResults}, configLoaderErrs, configLoaderWarnings
}

func evalInBackground(eng *engine.Engine, ctx context.Context, options engine.RunOptions, inputs []models.State) <-chan *engine.Results {
	results := make(chan *engine.Results)
	go func() {
		results <- eng.Eval(ctx, options, inputs)
	}()
	return results
}
