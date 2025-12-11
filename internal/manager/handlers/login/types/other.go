package types

import (
	"fmt"
)

type TooManyTasks struct {
	taskName string
}

func (t TooManyTasks) Error() string {
	return "too many requests"
}

func (t TooManyTasks) PrivateError() string {
	return fmt.Sprintf("too many tasks: %s", t.taskName)
}

func (t TooManyTasks) Code() int {
	return 9000
}

func NewTooManyTasks(taskName string) error {
	return TooManyTasks{taskName: taskName}
}
