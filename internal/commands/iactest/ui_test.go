package iactest_test

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-iac/internal/commands/iactest"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/stretchr/testify/mock"
)

type MockUserInterface struct {
	mock.Mock
}

func (m *MockUserInterface) Output(message string) error {
	args := m.Called(message)
	return args.Error(0)
}

func (m *MockUserInterface) OutputError(err error) error {
	args := m.Called(err)
	return args.Error(0)
}

func (m *MockUserInterface) NewProgressBar() ui.ProgressBar {
	args := m.Called()
	return args.Get(0).(ui.ProgressBar)
}

func (m *MockUserInterface) Input(prompt string) (string, error) {
	args := m.Called(prompt)
	return args.String(0), args.Error(1)
}

type MockProgressBar struct {
	mock.Mock
}

func (m *MockProgressBar) SetTitle(title string) {
	m.Called(title)
}

func (m *MockProgressBar) UpdateProgress(progress float64) error {
	args := m.Called(progress)
	return args.Error(0)
}

func (m *MockProgressBar) Clear() error {
	args := m.Called()
	return args.Error(0)
}

func TestDisplayTitle(t *testing.T) {
	backend := new(MockUserInterface)
	backend.On("NewProgressBar").Return(new(MockProgressBar))
	logger := zerolog.Nop()
	u := iactest.NewUI(iactest.UIConfig{
		Backend: backend,
		Logger:  &logger,
	})

	expectedOutput := "\nSnyk Infrastructure As Code\n"
	backend.On("Output", expectedOutput).Return(nil)
	u.DisplayTitle()

	backend.AssertCalled(t, "Output", expectedOutput)
}

func TestDisplayCompleted(t *testing.T) {
	backend := new(MockUserInterface)
	backend.On("NewProgressBar").Return(new(MockProgressBar))
	logger := zerolog.Nop()
	u := iactest.NewUI(iactest.UIConfig{
		Backend: backend,
		Logger:  &logger,
	})

	expectedOutput := "✔ Test completed."
	backend.On("Output", expectedOutput).Return(nil)
	u.DisplayCompleted()

	backend.AssertCalled(t, "Output", expectedOutput)
}

func TestProgressBar(t *testing.T) {
	backend := new(MockUserInterface)
	progressBar := new(MockProgressBar)
	logger := zerolog.Nop()

	expectedOutput := "Snyk testing Infrastructure as Code configuration issues."
	backend.On("NewProgressBar").Return(progressBar)
	progressBar.On("SetTitle", expectedOutput).Return()
	progressBar.On("UpdateProgress", ui.InfiniteProgress).Return(nil)
	progressBar.On("Clear").Return(nil)

	u := iactest.NewUI(iactest.UIConfig{
		Backend: backend,
		Logger:  &logger,
	})

	u.StartProgressBar()
	u.ClearProgressBar()

	progressBar.AssertCalled(t, "SetTitle", expectedOutput)
	progressBar.AssertCalled(t, "UpdateProgress", ui.InfiniteProgress)
	progressBar.AssertCalled(t, "Clear")
}

func TestDisabled(t *testing.T) {
	backend := new(MockUserInterface)
	progressBar := new(MockProgressBar)
	logger := zerolog.Nop()

	backend.On("NewProgressBar").Return(progressBar)
	u := iactest.NewUI(iactest.UIConfig{
		Backend:  backend,
		Logger:   &logger,
		Disabled: true,
	})

	u.DisplayTitle()
	u.StartProgressBar()
	u.ClearProgressBar()
	u.DisplayCompleted()

	backend.AssertNotCalled(t, "Output")
	progressBar.AssertNotCalled(t, "SetTitle")
	progressBar.AssertNotCalled(t, "UpdateProgress")
	progressBar.AssertNotCalled(t, "Clear")
}
