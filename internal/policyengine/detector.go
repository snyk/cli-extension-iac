package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/snyk/policy-engine/pkg/input"
	"gopkg.in/yaml.v3"
)

type syntaxValidator func(input *input.File) error

func validateJSON(i *input.File) error {
	contents, err := i.Contents()
	if err != nil {
		return err
	}

	var value any

	if err := json.Unmarshal(contents, &value); err != nil {
		return input.FailedToParseInput
	}

	var object struct{}

	if err := json.Unmarshal(contents, &object); err != nil {
		return input.InvalidInput
	}

	return nil
}

func validateYAML(i *input.File) error {
	contents, err := i.Contents()
	if err != nil {
		return err
	}

	{
		decoder := yaml.NewDecoder(bytes.NewReader(contents))

		for {
			var value any

			if err := decoder.Decode(&value); err == io.EOF {
				break
			} else if err != nil {
				return input.FailedToParseInput
			}
		}
	}

	{
		decoder := yaml.NewDecoder(bytes.NewReader(contents))

		for {
			var object struct{}

			if err := decoder.Decode(&object); err == io.EOF {
				break
			} else if err != nil {
				return input.InvalidInput
			}
		}
	}

	return nil
}

type errorsHandlingDetector struct {
	wrapped input.Detector
}

func (e errorsHandlingDetector) DetectDirectory(i *input.Directory, opts input.DetectOptions) (input.IACConfiguration, error) {
	return e.handleErrors(e.wrapped.DetectDirectory(i, opts))
}

func (e errorsHandlingDetector) DetectFile(i *input.File, opts input.DetectOptions) (input.IACConfiguration, error) {
	return e.handleErrors(e.wrapped.DetectFile(i, opts))
}

func (e errorsHandlingDetector) handleErrors(config input.IACConfiguration, err error) (input.IACConfiguration, error) {
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return config, nil
}

func newErrorsHandlingDetector(wrapped input.Detector) errorsHandlingDetector {
	return errorsHandlingDetector{
		wrapped: wrapped,
	}
}

func newDetector() *detector {
	var (
		cloudFormation       = newErrorsHandlingDetector(&input.CfnDetector{})
		terraformPlan        = newErrorsHandlingDetector(&input.TfPlanDetector{})
		terraform            = newErrorsHandlingDetector(&input.TfDetector{})
		terraformState       = newErrorsHandlingDetector(&input.TfStateDetector{})
		kubernetes           = newErrorsHandlingDetector(&input.KubernetesDetector{})
		azureResourceManager = newErrorsHandlingDetector(&input.ArmDetector{})
	)

	return &detector{
		directoryDelegates: []input.Detector{
			terraform,
		},
		fileDelegates: map[string][]input.Detector{
			".yaml": {
				cloudFormation,
				kubernetes,
			},
			".yml": {
				cloudFormation,
				kubernetes,
			},
			".json": {
				cloudFormation,
				terraformPlan,
				terraformState,
				azureResourceManager,
			},
			".tf": {
				terraform,
			},
		},
		syntaxValidators: map[string]syntaxValidator{
			".json": validateJSON,
			".yaml": validateYAML,
			".yml":  validateYAML,
		},
	}
}

type detector struct {
	directoryDelegates []input.Detector
	fileDelegates      map[string][]input.Detector
	syntaxValidators   map[string]syntaxValidator
}

func (d *detector) DetectDirectory(i *input.Directory, opts input.DetectOptions) (input.IACConfiguration, error) {
	var lastError error

	for _, delegate := range d.directoryDelegates {
		if config, err := delegate.DetectDirectory(i, opts); err != nil {
			lastError = err
		} else if config != nil {
			return config, nil
		}
	}

	return nil, lastError
}

func (d *detector) DetectFile(i *input.File, opts input.DetectOptions) (input.IACConfiguration, error) {
	extension := strings.ToLower(filepath.Ext(i.GetPath()))

	// The Policy Engine sometimes returns an input.FailedToParseInput error when
	// a file has the wrong "shape". For example, an ARM template must always be a
	// JSON object. If the parsed file contains a JSON array instead, the ARM
	// input detector returns an input.FailedToParseInput error instead of the
	// more correct input.InvalidInput. The validation below returns
	// input.FailedToParseInput and input.InvalidInput for the right conditions.

	if validateSyntax, ok := d.syntaxValidators[extension]; ok {
		if err := validateSyntax(i); err != nil {
			return nil, err
		}
	}

	var lastError error

	for _, delegate := range d.fileDelegates[extension] {
		if config, err := delegate.DetectFile(i, opts); err != nil {
			lastError = err
		} else if config != nil {
			return config, nil
		}
	}

	return nil, lastError
}
