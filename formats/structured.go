package formats

import (
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v2"
)

type JsonRenderer[T any] struct{}

func (r *JsonRenderer[T]) Render(w io.Writer, view View[T], rows []T) error {
	json, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal rows: %w", err)
	}
	_, err = fmt.Fprintln(w, string(json))
	if err != nil {
		return fmt.Errorf("unable to write JSON output: %w", err)
	}
	return nil
}

type YamlRenderer[T any] struct{}

func (r *YamlRenderer[T]) Render(w io.Writer, view View[T], rows []T) error {
	yamlData, err := yaml.Marshal(rows)
	if err != nil {
		return fmt.Errorf("unable to marshal data to YAML: %w", err)
	}
	_, err = fmt.Fprintln(w, string(yamlData))
	if err != nil {
		return fmt.Errorf("unable to write YAML output: %w", err)
	}
	return nil
}
