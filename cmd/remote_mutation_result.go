package cmd

import "errors"

type remoteMutationResultState uint8

const (
	remoteMutationResultUncertain remoteMutationResultState = iota + 1
	remoteMutationResultOutputIncomplete
)

type remoteMutationResultError struct {
	state remoteMutationResultState
	err   error
}

func (err *remoteMutationResultError) Error() string {
	return err.err.Error()
}

func (err *remoteMutationResultError) Unwrap() error {
	return err.err
}

func markRemoteMutationResult(err error, state remoteMutationResultState) error {
	if err == nil {
		return nil
	}
	return &remoteMutationResultError{state: state, err: err}
}

func remoteMutationResultStateOf(err error) (remoteMutationResultState, bool) {
	var resultErr *remoteMutationResultError
	if !errors.As(err, &resultErr) {
		return 0, false
	}
	return resultErr.state, true
}
