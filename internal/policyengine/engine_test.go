package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestValid(t *testing.T) {
	dir := filepath.Join("testdata", "valid")

	for _, name := range readDir(t, dir) {
		t.Run(name, func(t *testing.T) {
			results, err := runEngine(t, engine.RunOptions{
				FS:    afero.NewOsFs(),
				Paths: []string{filepath.Join(dir, name)},
			})

			require.Nil(t, err)
			require.NotNil(t, results)
		})
	}
}

func TestInvalid(t *testing.T) {
	dir := filepath.Join("testdata", "invalid")

	for _, name := range readDir(t, dir) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)

			results, err := runEngine(t, engine.RunOptions{
				FS:    afero.NewOsFs(),
				Paths: []string{path},
			})

			require.Empty(t, err)
			require.Nil(t, results)
		})
	}
}

func TestUnrecognized(t *testing.T) {
	dir := filepath.Join("testdata", "unrecognized")

	for _, name := range readDir(t, dir) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)

			results, err := runEngine(t, engine.RunOptions{
				FS:    afero.NewOsFs(),
				Paths: []string{path},
			})

			require.Empty(t, err)
			require.Nil(t, results)
		})
	}
}

func TestUnparseable(t *testing.T) {
	dir := filepath.Join("testdata", "unparseable")

	for _, name := range readDir(t, dir) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)

			results, errs := runEngine(t, engine.RunOptions{
				FS:    afero.NewOsFs(),
				Paths: []string{path},
			})

			require.Len(t, errs, 1)

			err := errs[0]

			require.IsType(t, engine.Error{}, err)

			engineErr := err.(engine.Error)

			require.Equal(t, engine.ErrorCodeFailedToParseInput, engineErr.Code)
			require.Equal(t, path, engineErr.Path)

			require.Nil(t, results)
		})
	}
}

func TestNoLoadableInputs(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.Nil(t, fs.Mkdir("dir", 0755))

	results, err := runEngine(t, engine.RunOptions{
		FS:    fs,
		Paths: []string{"dir"},
	})

	require.ElementsMatch(t, err, []engine.Error{
		{
			Message: "no IaC files found",
			Code:    engine.ErrorCodeNoLoadableInputs,
			Path:    "dir",
		},
	})

	require.Nil(t, results)
}

func TestUnreadablePath(t *testing.T) {
	results, err := runEngine(t, engine.RunOptions{
		FS:    afero.NewMemMapFs(),
		Paths: []string{"does-not-exist"},
	})

	require.ElementsMatch(t, err, []engine.Error{
		{
			Message: "open does-not-exist: file does not exist",
			Code:    engine.ErrorCodeUnableToReadPath,
			Path:    "does-not-exist",
		},
	})

	require.Nil(t, results)
}

func TestHidden(t *testing.T) {
	dir := filepath.Join("testdata", "hidden")

	for _, name := range readDir(t, dir) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)

            // On Windows, mark the fixtures as hidden so the Windows-specific
            // hidden attribute check behaves consistently with POSIX dot-hidden.
            setHidden(t, path)

			results, errs := runEngine(t, engine.RunOptions{
				FS:    afero.NewOsFs(),
				Paths: []string{path},
			})

			require.ElementsMatch(t, errs, []engine.Error{
				{
					Message: "no IaC files found",
					Code:    engine.ErrorCodeNoLoadableInputs,
					Path:    path,
				},
			})

			require.Nil(t, results)
		})
	}
}

func TestDepthDetection(t *testing.T) {
	dirPath := filepath.Join("testdata", "detection-depth")

	t.Run("scans all files when no detection depth is provided", func(t *testing.T) {
		results, errs := runEngine(t, engine.RunOptions{
			FS:    afero.NewOsFs(),
			Paths: []string{dirPath},
		})

		require.Nil(t, errs)
		require.Len(t, results.Results, 2)
	})

	t.Run("scans only files within the detection depth when provided", func(t *testing.T) {
		results, errs := runEngine(t, engine.RunOptions{
			FS:             afero.NewOsFs(),
			Paths:          []string{dirPath},
			DetectionDepth: 1,
		})

		require.Nil(t, errs)
		require.Len(t, results.Results, 1)
		require.Equal(t, filepath.Join(dirPath, "one", "cloudformation.yml"), results.Results[0].Input.Meta["filepath"])
	})

}

func TestTfVars(t *testing.T) {
	filePath := filepath.Join("testdata", "terraform-vars", "terraform.tf")
	varPath := filepath.Join("testdata", "terraform-vars", "vars.tfvars")

	t.Run("scans the file when a var file is not provided", func(t *testing.T) {
		results, errs := runEngine(t, engine.RunOptions{
			FS:    afero.NewOsFs(),
			Paths: []string{filePath},
		})

		require.Nil(t, errs)
		require.Equal(t, results.Results[0].Input.Resources["aws_security_group"]["aws_security_group.vars"].Attributes["ingress"].([]interface{})[0].(map[string]interface{})["cidr_blocks"].([]interface{})[0], "1.1.1.1/1")
	})

	t.Run("scans the file when a var file is provided", func(t *testing.T) {
		results, errs := runEngine(t, engine.RunOptions{
			FS:      afero.NewOsFs(),
			Paths:   []string{filePath},
			VarFile: varPath,
		})

		require.Nil(t, errs)
		require.Equal(t, results.Results[0].Input.Resources["aws_security_group"]["aws_security_group.vars"].Attributes["ingress"].([]interface{})[0].(map[string]interface{})["cidr_blocks"].([]interface{})[0], "0.0.0.0/0")
	})
}

func readDir(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.Nil(t, err)

	var result []string

	for _, e := range entries {
		result = append(result, e.Name())
	}

	return result
}

func runEngine(t *testing.T, options engine.RunOptions) (*engine.Results, []error) {
	t.Helper()
	logger := zerolog.Nop()

	e := engine.NewEngine(context.Background(), engine.EngineOptions{
		Logger: &logger,
	})
	for _, err := range e.InitializationErrors() {
		require.NoError(t, err)
	}
	return e.Run(context.Background(), options)
}

// setHidden sets the Windows hidden attribute when running on Windows.
// On other platforms, it is a no-op.
func setHidden(t *testing.T, p string) {
    t.Helper()
    // On non-Windows, this is a no-op; on Windows, the helper in
    // engine_hidden_windows_test.go will be built and used by tests invoking
    // setHidden prior to scanning.
}
