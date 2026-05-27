package common

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type HealthOutput struct {
	Body struct{}
}

func AddRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "health",
		Method:       http.MethodGet,
		Path:         "/v1/health",
		Summary:      "Health check",
		MaxBodyBytes: 1024,
	}, func(ctx context.Context, input *struct{}) (*HealthOutput, error) {
		return &HealthOutput{}, nil
	})
}
