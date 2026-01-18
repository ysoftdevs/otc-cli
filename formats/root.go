package formats

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/table"
)

func newRenderer[T any](format string) (Renderer[T], error) {
	switch format {
	case "json":
		return &JsonRenderer[T]{}, nil
	case "yaml":
		return &YamlRenderer[T]{}, nil
	default:
		return &PrettyTableRenderer[T]{
			Style: table.StyleLight,
		}, nil
	}
}

func PrintFormatted[T any](format string, data []T, view View[T]) error {
	renderer, err := newRenderer[T](format)
	if err != nil {
		return fmt.Errorf("failed to create renderer: %w", err)
	}

	err = renderer.Render(os.Stdout, view, data)
	if err != nil {
		return fmt.Errorf("failed to render data: %w", err)
	}

	return nil
}
