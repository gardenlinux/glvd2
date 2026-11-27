package presentation

import (
	"context"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

// RecordWalker walks assessment records one at a time for rendering.
type RecordWalker interface {
	Walk(ctx context.Context, fn func(assessment.Record) error) error
}
