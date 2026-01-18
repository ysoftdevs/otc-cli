package formats

import (
	"fmt"
	"io"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
)

type View[T any] struct {
	Columns []Column[T]
}

type Column[T any] struct {
	Name   string
	Value  func(T) any
	Format Formatter
	Align  Align
	Hidden bool
}

type Formatter func(any) string

type Align int

const (
	AlignLeft Align = iota
	AlignRight
)

func Col[T any, V any](
	name string,
	getter func(T) V,
	opts ...ColumnOption[T],
) Column[T] {
	c := Column[T]{
		Name:  name,
		Value: func(t T) any { return getter(t) },
		Format: func(v any) string {
			return fmt.Sprint(v)
		},
		Align: AlignLeft,
	}

	for _, opt := range opts {
		opt(&c)
	}

	return c
}

type ColumnOption[T any] func(*Column[T])

func RightAlign[T any]() ColumnOption[T] {
	return func(c *Column[T]) {
		c.Align = AlignRight
	}
}

func Time[T any](layout string) ColumnOption[T] {
	return func(c *Column[T]) {
		c.Format = func(v any) string {
			if t, ok := v.(time.Time); ok {
				return t.Format(layout)
			}
			return ""
		}
	}
}

func BoolYesNo[T any]() ColumnOption[T] {
	return func(c *Column[T]) {
		c.Format = func(v any) string {
			if b, ok := v.(bool); ok {
				if b {
					return "yes"
				}
				return "no"
			}
			return ""
		}
	}
}

type Renderer[T any] interface {
	Render(w io.Writer, view View[T], rows []T) error
}

type PrettyTableRenderer[T any] struct {
	Style table.Style
}

func (r PrettyTableRenderer[T]) Render(
	w io.Writer,
	view View[T],
	rows []T,
) error {

	t := table.NewWriter()
	t.SetOutputMirror(w)

	t.SetStyle(r.Style)

	// headers
	header := table.Row{}
	colMap := make([]Column[T], 0, len(view.Columns))

	for _, c := range view.Columns {
		if c.Hidden {
			continue
		}
		header = append(header, c.Name)
		colMap = append(colMap, c)
	}

	t.AppendHeader(header)

	// rows
	for _, row := range rows {
		r := table.Row{}
		for _, col := range colMap {
			v := col.Value(row)
			r = append(r, col.Format(v))
		}
		t.AppendRow(r)
	}

	// alignment
	configs := []table.ColumnConfig{}
	for i, col := range colMap {
		if col.Align == AlignRight {
			configs = append(configs, table.ColumnConfig{
				Number: i + 1,
				Align:  text.AlignRight,
			})
		}
	}
	t.SetColumnConfigs(configs)

	t.Render()
	return nil
}
