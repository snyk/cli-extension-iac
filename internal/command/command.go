package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/version"
	"github.com/spf13/afero"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/cli-extension-iac/internal/settings"
)

type Engine interface {
	Run(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error)
}

type ResultsProcessor interface {
	ProcessResults(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error)
}

type SettingsReader interface {
	ReadSettings(ctx context.Context) (*settings.Settings, error)
}

type BundleDownloader interface {
	DownloadLatestBundle(policyEngineVersion string, w io.Writer) error
}

type Command struct {
	Output                  string
	Logger                  *zerolog.Logger
	FS                      afero.Fs
	Engine                  Engine
	Paths                   []string
	Bundle                  string
	ResultsProcessor        ResultsProcessor
	SnykCloudEnvironment    string
	SnykClient              cloudapi.Client
	Scan                    string
	DetectionDepth          int
	VarFile                 string
	SettingsReader          SettingsReader
	BundleDownloader        BundleDownloader
	ReadPolicyEngineVersion func() (string, error)
	ExcludeRawResults       bool
	AllowAnalytics          bool
	Report                  bool
	IacNewEngine            bool
}

func (c Command) Run() int {
	if _, err := c.RunWithError(); err != nil {
		c.Logger.Error().Err(err).Send()
		return 1
	}

	return 0
}

func (c Command) RunWithError() (bool, error) {
	output := c.scan()
	isSuccessful := false
	if len(output.scanErrors) == 0 {
		isSuccessful = true
	}

	err := c.print(output)
	if err != nil {
		return isSuccessful, err
	}

	isSuccessful = false

	return isSuccessful, nil
}

func (c Command) scan() scanOutput {
	var output scanOutput
	ctx := context.Background()

	userSettings, err := c.SettingsReader.ReadSettings(ctx)
	if err != nil {
		c.Logger.Error().Err(err).Msg("read settings")
		return output.addScanErrors(errReadSettings)
	}

	output = output.setSettings(userSettings)

	if !userSettings.Entitlements.InfrastructureAsCode {
		return output.addScanErrors(errEntitlementInfrastructureAsCodeNotEnabled)
	}

	paths, err := normalizePaths(c.Paths)
	if err != nil {
		c.Logger.Error().Err(err).Msg("normalize paths")
		return output.addScanErrors(errScan)
	}

	var validPaths []string

	for _, path := range paths {
		if strings.Contains(path, "..") {
			output = output.addScanErrors(cwdTraversalError(path))
		} else {
			validPaths = append(validPaths, path)
		}
	}

	if len(validPaths) == 0 {
		return output.addScanErrors(errNoPaths)
	}

	bundle, err := c.openBundle()
	if err != nil {
		return output.addScanErrors(errOpenBundle)
	}

	customRules, err := c.customRuleBundles(ctx, userSettings.OrgPublicID)
	if err != nil {
		return output.addScanErrors(errFetchCustomRulesBundles)
	}

	engineResults, engineAnalytics, engineErrors, engineWarnings := c.Engine.Run(ctx, engine.RunOptions{
		Paths:                validPaths,
		SnykBundle:           bundle,
		CustomRuleBundles:    customRules,
		OrgPublicID:          userSettings.OrgPublicID,
		SnykCloudEnvironment: c.SnykCloudEnvironment,
		SnykClient:           c.SnykClient,
		Scan:                 c.Scan,
		DetectionDepth:       c.DetectionDepth,
		VarFile:              c.VarFile,
		Logger:               c.Logger,
	})

	if !c.ExcludeRawResults {
		output = output.setEngineResults(engineResults)
	}
	output = output.setEngineAnalytics(engineAnalytics)
	output = output.addScanErrors(errorsToScanErrors(engineErrors)...)
	output = output.addScanWarnings(errorsToScanErrors(engineWarnings)...)

	if scanResults, err := c.ResultsProcessor.ProcessResults(engineResults, engineAnalytics); err != nil {
		c.Logger.Error().Err(err).Msg("process results")
		output = output.addScanErrors(errProcessResults)
	} else {
		output = output.setScanResults(scanResults)
	}

	return output
}

func (c Command) print(output scanOutput) (e error) {
	w, err := c.openOutput()
	if err != nil {
		return fmt.Errorf("open output: %v", err)
	}

	defer func() {
		if err := w.Close(); err != nil && e == nil {
			e = fmt.Errorf("close output: %v", err)
		}
	}()

	return c.writeOutput(w, output)
}

func (c Command) writeOutput(w io.Writer, output scanOutput) error {
	type ignoreSettings struct {
		AdminOnly                  bool `json:"adminOnly"`
		DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
		ReasonRequired             bool `json:"reasonRequired"`
	}

	type userSettings struct {
		Org            string         `json:"org"`
		IgnoreSettings ignoreSettings `json:"ignoreSettings"`
	}

	type outputData struct {
		Results    *results.Results `json:"results,omitempty"`
		RawResults *engine.Results  `json:"rawResults,omitempty"`
		Errors     []scanError      `json:"errors,omitempty"`
		Warnings   []scanError      `json:"warnings,omitempty"`
		Settings   userSettings     `json:"settings"`
	}

	data := outputData{
		Results:    output.scanResults,
		RawResults: output.engineResults,
		Errors:     output.scanErrors,
		Warnings:   output.scanWarnings,
	}

	if output.settings != nil {
		data.Settings.Org = output.settings.Org
		data.Settings.IgnoreSettings.AdminOnly = output.settings.IgnoreSettings.AdminOnly
		data.Settings.IgnoreSettings.DisregardFilesystemIgnores = output.settings.IgnoreSettings.DisregardFilesystemIgnores
		data.Settings.IgnoreSettings.ReasonRequired = output.settings.IgnoreSettings.ReasonRequired
	}

	return json.NewEncoder(w).Encode(data)
}

func (c Command) openBundle() (io.ReadCloser, error) {
	if c.Bundle != "" {
		c.Logger.Info().Msg("using the local bundle")
		return c.FS.Open(c.Bundle)
	}

	policyEngineVersion, err := c.ReadPolicyEngineVersion()

	if err != nil {
		return nil, fmt.Errorf("find policy-engine dependency version %v", err)
	}

	c.Logger.Info().Msgf("using policy engine version: %s", policyEngineVersion)
	c.Logger.Info().Msgf("using Terraform version: %s", version.TerraformVersion)
	c.Logger.Info().Msgf("using OPA version: %s", version.OPAVersion)

	var buffer bytes.Buffer

	if err := c.BundleDownloader.DownloadLatestBundle(policyEngineVersion, &buffer); err != nil {
		return nil, fmt.Errorf("download bundle: %v", err)
	}

	return io.NopCloser(&buffer), nil
}

func (c Command) customRuleBundles(ctx context.Context, orgID string) ([]bundle.Reader, error) {
	if orgID == "" {
		return nil, nil
	}

	bundles, err := c.SnykClient.CustomRules(ctx, orgID)
	if err != nil {
		switch {
		case errors.Is(err, cloudapi.ErrForbidden):
			return nil, nil
		default:
			return nil, fmt.Errorf("read custom rules: %v", err)
		}
	}

	return bundles, nil
}

func (c Command) openOutput() (io.WriteCloser, error) {
	if c.Output != "" {
		return c.FS.Create(c.Output)
	}

	return nopCloser{os.Stdout}, nil
}

func ReadRuntimePolicyEngineVersion() (string, error) {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("build info not available")
	}

	const path = "github.com/snyk/policy-engine"

	for _, dep := range buildInfo.Deps {
		if dep.Path == path {
			return dep.Version, nil
		}
	}

	return "", fmt.Errorf("dependency %v not found in build info", path)
}

// scanOutput is a copy-on-write data structure that accumulates output data.
// The copy-on-write discipline is respected as long as scanOutput is only
// modified through the setter methods.
type scanOutput struct {
	engineResults   *engine.Results
	engineAnalytics results.ScanAnalytics
	scanResults     *results.Results
	scanErrors      []scanError
	scanWarnings    []scanError
	settings        *settings.Settings
}

func (o scanOutput) setEngineResults(engineResults *engine.Results) scanOutput {
	o.engineResults = engineResults
	return o
}

func (o scanOutput) setEngineAnalytics(engineAnalytics results.ScanAnalytics) scanOutput {
	o.engineAnalytics = engineAnalytics
	return o
}

func (o scanOutput) setScanResults(scanResults *results.Results) scanOutput {
	o.scanResults = scanResults
	return o
}

func (o scanOutput) addScanErrors(errors ...scanError) scanOutput {
	var scanErrors []scanError

	scanErrors = append(scanErrors, o.scanErrors...)
	scanErrors = append(scanErrors, errors...)

	o.scanErrors = scanErrors

	return o
}

func (o scanOutput) addScanWarnings(warnings ...scanError) scanOutput {
	var scanWarnings []scanError

	scanWarnings = append(scanWarnings, o.scanWarnings...)
	scanWarnings = append(scanWarnings, warnings...)

	o.scanWarnings = scanWarnings

	return o
}

func (o scanOutput) setSettings(settings *settings.Settings) scanOutput {
	o.settings = settings
	return o
}

type nopCloser struct {
	io.Writer
}

func (c nopCloser) Write(p []byte) (n int, err error) {
	return c.Writer.Write(p)
}

func (c nopCloser) Close() error {
	return nil
}
