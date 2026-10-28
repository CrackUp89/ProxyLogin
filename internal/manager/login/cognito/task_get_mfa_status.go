package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type getMFAStatusTaskResult struct {
	withResultBase
	status *loginTypes.MFAStatus
}

func (g *getMFAStatusTaskResult) GetPayload() any {
	return g.status
}

func (g *getMFAStatusTaskResult) SetPayload(_ any) {
	panic("should not be called")
}

type getMFAStatusTaskResultChan chan *getMFAStatusTaskResult

type getMFAStatusTask struct {
	withAuth
	Task[getMFAStatusTaskResult, *getMFAStatusTaskResult]
}

func (t getMFAStatusTask) Process(c *Cognito) {
	t.ResultChan <- c.processGetMFAStatusTask(t)
}

func (c *Cognito) createGetMFAStatusTask(ctx context.Context, auth any) (getMFAStatusTaskResultChan, loginTypes.GenericError) {
	resultChan := make(getMFAStatusTaskResultChan)
	err := c.appendGetMFAStatusTask(getMFAStatusTask{
		Auth:       auth,
		Context:    ctx,
		ResultChan: resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processGetMFAStatusTask(task getMFAStatusTask) *getMFAStatusTaskResult {
	ef := genericTaskErrorFactory[getMFAStatusTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	tokenSet, r := checkAuth(c, task.Task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	result, err := c.getUserFromAuthToken(task.Context, tokenSet.AccessToken)
	if err != nil {
		return ef(err)
	}

	status := &loginTypes.MFAStatus{
		MFAMethods: []loginTypes.MFAType{},
	}

	if result.UserMFASettingList != nil {
		status.MFAEnabled = len(result.UserMFASettingList) > 0
		status.MFAMethods = mapMFAList(result.UserMFASettingList)
		for _, mfa := range status.MFAMethods {
			switch mfa {
			case loginTypes.MFATypeEMAIL:
				status.EMAILConfigured = true
			case loginTypes.MFATypeSoftwareToken:
				status.TOTPConfigured = true
			case loginTypes.MFATypeSMS:
				status.SMSConfigured = true
			}
		}
	} else {
		if c.poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOn {
			status.MFAEnabled = true
		}
	}

	if result.PreferredMfaSetting != nil {
		status.PreferredMFA = mfaMapping[*result.PreferredMfaSetting]
	}

	for _, attr := range result.UserAttributes {
		switch *attr.Name {
		case "phone_number":
			status.HasPhoneNumber = true
			status.PhoneNumber = *attr.Value
		case "phone_number_verified":
			status.PhoneVerified = *attr.Value == "true"
		}
	}

	return &getMFAStatusTaskResult{
		status: status,
	}
}
