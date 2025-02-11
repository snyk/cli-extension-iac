package iactest

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
)

const (
	Title          = "Snyk Infrastructure As Code"
	ProgressText   = "Snyk testing Infrastructure as Code configuration issues."
	CompletionText = "Test completed."
)

type iacTestUI struct {
	logger   *zerolog.Logger
	disabled bool
	backend  ui.UserInterface
	bar      ui.ProgressBar
}

type UIConfig struct {
	Disabled bool
	Backend  ui.UserInterface
	Logger   *zerolog.Logger
}

func NewUI(config UIConfig) *iacTestUI {
	return &iacTestUI{
		logger:   config.Logger,
		disabled: config.Disabled,
		backend:  config.Backend,
		bar:      config.Backend.NewProgressBar(),
	}
}

func (u *iacTestUI) DisplayTitle() {
	if u.disabled {
		return
	}

	u.backend.Output(fmt.Sprintf("\n%s\n", renderBold(Title)))
}

func (u *iacTestUI) DisplayCompleted() {
	if u.disabled {
		return
	}

	u.backend.Output(fmt.Sprintf("%s %s", renderGreen("✔"), CompletionText))
}

func (u *iacTestUI) StartProgressBar() {
	if u.disabled {
		return
	}

	u.bar.SetTitle(ProgressText)

	err := u.bar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		u.logger.Err(err).Msg("Failed to update progress")
	}
}

func (u *iacTestUI) ClearProgressBar() {
	if u.disabled {
		return
	}

	err := u.bar.Clear()
	if err != nil {
		u.logger.Err(err).Msg("Failed to clear progress")
	}
}

func renderBold(str string) string {
	return lipgloss.NewStyle().Bold(true).Render(str)
}

func renderGreen(str string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(str)
}
