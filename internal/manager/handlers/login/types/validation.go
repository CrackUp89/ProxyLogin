package types

import (
	"fmt"
	"strings"
)

type ValidationIssues = map[string]string

type ValidationError struct {
	issues ValidationIssues
}

func (e *ValidationError) Error() string {
	issueDesc := make([]string, 0, len(e.issues))
	for k, v := range e.issues {
		issueDesc = append(issueDesc, fmt.Sprintf("%s: %s", k, v))
	}
	return fmt.Sprintf("validation issues - %s", strings.Join(issueDesc, "; "))
}

func NewValidationError(issues ValidationIssues) *ValidationError {
	return &ValidationError{issues}
}
