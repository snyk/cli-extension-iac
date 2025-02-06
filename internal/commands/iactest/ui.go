package iactest

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
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

func (u *iacTestUI) Output(message string) {
	if u.disabled {
		return
	}

	u.backend.Output(message)
}

func (u *iacTestUI) StartProgressBar(message string) {
	if u.disabled {
		return
	}

	u.bar.SetTitle(message)

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
