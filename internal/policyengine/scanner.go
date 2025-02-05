package engine

import (
	"github.com/rs/zerolog"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/postprocess"
	"github.com/spf13/afero"
)

type scanner struct {
	fs             afero.Fs
	varFile        string
	logger         *zerolog.Logger
	loader         input.Loader
	detectionDepth int
	errors         []error
	warnings       []error
}

func (e *scanner) scan(paths []string) (input.Loader, []error, []error) {
	e.errors = nil
	e.loader = input.NewLoader(newDetector())

	e.loadPaths(paths)

	return e.loader, e.errors, e.warnings
}

func annotate(results *Results, loader input.Loader) {
	postprocess.AddSourceLocs(results, loader)
}

func filter(results *Results, options RunOptions) {
	if options.Scan == "resource-changes" {
		postprocess.ResourceFilter(results, tfPlanFilter)
	}
}

func tfPlanFilter(resource *models.ResourceState) bool {
	if tfplanMeta, ok := resource.Meta["tfplan"].(map[string]interface{}); ok {
		if resourceActions, ok := tfplanMeta["resource_actions"].([]interface{}); ok {
			for _, resourceAction := range resourceActions {
				if str, ok := resourceAction.(string); ok {
					if str == "create" || str == "update" {
						return true
					}
				}
			}
		}
		return false
	}
	return true
}

func (e *scanner) loadPaths(paths []string) {
	for _, path := range paths {
		e.loadPath(path)
	}
	// All errors in Errors() are considered non-fatal
	for path, errs := range e.loader.Errors() {
		for _, err := range errs {
			e.logger.Warn().Err(err).Msg("Non-fatal error")
			if unwrapped := unwrapEngineWarning(err, path); unwrapped != nil {
				e.warnings = append(e.warnings, unwrapped)
			}
		}
	}
}

func (e *scanner) loadPath(path string) {
	if stat, err := e.fs.Stat(path); err != nil {
		e.errors = append(e.errors, Error{
			Message: err.Error(),
			Code:    ErrorCodeUnableToReadPath,
			Path:    path,
		})
	} else if stat.IsDir() {
		e.loadDirectory(path)
	} else {
		e.loadFile(path)
	}
}

func (e *scanner) loadDirectory(path string) {
	loaderCountBefore := e.loader.Count()
	errorsCountBefore := len(e.errors)

	e.walkDirectory(path)

	loaderCountAfter := e.loader.Count()
	errorsCountAfter := len(e.errors)

	// If the following conditions is true, scanning this path didn't make any
	// progress. If we don't have a higher loaderCount, we couldn't find any
	// valid IaC files. If we don't have a higher errorCount, this means that no
	// new errors were generated. But, if this path is a file or a non-empty
	// directory, there should be at least a file that throws some kind of error
	// (unrecognized, unreadable, etc.). If this is not the case, then throw an
	// error scoped to this path, so it can be reported back to the user.

	if loaderCountBefore == loaderCountAfter && errorsCountBefore == errorsCountAfter {
		e.errors = append(e.errors, Error{
			Message: "no IaC files found",
			Code:    ErrorCodeNoLoadableInputs,
			Path:    path,
		})
	}
}

func (e *scanner) walkDirectory(path string) {
	dir := e.newDirectory(path)

	if e.load(dir) {
		return
	}

	// The directory was not loaded by the Policy Engine, which means it was not
	// recognized to be a collection of IaC files. Iterate over its content and
	// check whether we can load any of the files or subdirectories under it.

	walkFunc := func(d input.Detectable, depth int) (skip bool, err error) {
		if e.detectionDepth > 0 && depth-1 > e.detectionDepth {
			return true, nil
		}

		if hidden, err := isHidden(d.GetPath()); hidden || err != nil {
			return true, err
		}

		return e.load(d), nil
	}

	if err := dir.Walk(walkFunc); err != nil {
		if unwrapped := unwrapEngineError(err, path); unwrapped != nil {
			e.errors = append(e.errors, unwrapped)
		}
	}
}

func (e *scanner) loadFile(path string) {
	e.load(e.newFile(path))
}

func (e *scanner) newDirectory(path string) *input.Directory {
	return &input.Directory{
		Path: path,
		Fs:   e.fs,
	}
}

func (e *scanner) newFile(p string) *input.File {
	return &input.File{
		Path: p,
		Fs:   e.fs,
	}
}

func (e *scanner) load(d input.Detectable) bool {
	var varFiles []string

	if e.varFile != "" {
		varFiles = []string{e.varFile}
	}

	loaded, err := e.loader.Load(d, input.DetectOptions{VarFiles: varFiles})
	if err != nil {
		if unwrapped := unwrapEngineError(err, d.GetPath()); unwrapped != nil {
			e.errors = append(e.errors, unwrapped)
		}
	}

	return loaded
}
