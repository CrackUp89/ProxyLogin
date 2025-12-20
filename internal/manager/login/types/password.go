package types

type resetPasswordSessionExpiredOrDoesNotExistError struct{}

func (s *resetPasswordSessionExpiredOrDoesNotExistError) Error() string {
	return "Session expired or does not exist"
}

func (s *resetPasswordSessionExpiredOrDoesNotExistError) PrivateError() string {
	return "Session expired or does not exist"
}

func (s *resetPasswordSessionExpiredOrDoesNotExistError) Code() int {
	return 3000
}

var ResetPasswordSessionExpiredOrDoesNotExistError = resetPasswordSessionExpiredOrDoesNotExistError{}
