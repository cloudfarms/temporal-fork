// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Copyright (c) 2020 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Code generated by MockGen. DO NOT EDIT.
// Source: executable_task.go

// Package replication is a generated GoMock package.
package replication

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	backoff "go.temporal.io/server/common/backoff"
	definition "go.temporal.io/server/common/definition"
	serviceerror "go.temporal.io/server/common/serviceerror"
	tasks "go.temporal.io/server/common/tasks"
)

// MockExecutableTask is a mock of ExecutableTask interface.
type MockExecutableTask struct {
	ctrl     *gomock.Controller
	recorder *MockExecutableTaskMockRecorder
}

// MockExecutableTaskMockRecorder is the mock recorder for MockExecutableTask.
type MockExecutableTaskMockRecorder struct {
	mock *MockExecutableTask
}

// NewMockExecutableTask creates a new mock instance.
func NewMockExecutableTask(ctrl *gomock.Controller) *MockExecutableTask {
	mock := &MockExecutableTask{ctrl: ctrl}
	mock.recorder = &MockExecutableTaskMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockExecutableTask) EXPECT() *MockExecutableTaskMockRecorder {
	return m.recorder
}

// Ack mocks base method.
func (m *MockExecutableTask) Ack() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Ack")
}

// Ack indicates an expected call of Ack.
func (mr *MockExecutableTaskMockRecorder) Ack() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ack", reflect.TypeOf((*MockExecutableTask)(nil).Ack))
}

// Attempt mocks base method.
func (m *MockExecutableTask) Attempt() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Attempt")
	ret0, _ := ret[0].(int)
	return ret0
}

// Attempt indicates an expected call of Attempt.
func (mr *MockExecutableTaskMockRecorder) Attempt() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attempt", reflect.TypeOf((*MockExecutableTask)(nil).Attempt))
}

// Cancel mocks base method.
func (m *MockExecutableTask) Cancel() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Cancel")
}

// Cancel indicates an expected call of Cancel.
func (mr *MockExecutableTaskMockRecorder) Cancel() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cancel", reflect.TypeOf((*MockExecutableTask)(nil).Cancel))
}

// DeleteWorkflow mocks base method.
func (m *MockExecutableTask) DeleteWorkflow(ctx context.Context, workflowKey definition.WorkflowKey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteWorkflow", ctx, workflowKey)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteWorkflow indicates an expected call of DeleteWorkflow.
func (mr *MockExecutableTaskMockRecorder) DeleteWorkflow(ctx, workflowKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteWorkflow", reflect.TypeOf((*MockExecutableTask)(nil).DeleteWorkflow), ctx, workflowKey)
}

// GetNamespaceInfo mocks base method.
func (m *MockExecutableTask) GetNamespaceInfo(namespaceID string) (string, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespaceInfo", namespaceID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetNamespaceInfo indicates an expected call of GetNamespaceInfo.
func (mr *MockExecutableTaskMockRecorder) GetNamespaceInfo(namespaceID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespaceInfo", reflect.TypeOf((*MockExecutableTask)(nil).GetNamespaceInfo), namespaceID)
}

// IsRetryableError mocks base method.
func (m *MockExecutableTask) IsRetryableError(err error) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRetryableError", err)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsRetryableError indicates an expected call of IsRetryableError.
func (mr *MockExecutableTaskMockRecorder) IsRetryableError(err interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRetryableError", reflect.TypeOf((*MockExecutableTask)(nil).IsRetryableError), err)
}

// Nack mocks base method.
func (m *MockExecutableTask) Nack(err error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Nack", err)
}

// Nack indicates an expected call of Nack.
func (mr *MockExecutableTaskMockRecorder) Nack(err interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Nack", reflect.TypeOf((*MockExecutableTask)(nil).Nack), err)
}

// Reschedule mocks base method.
func (m *MockExecutableTask) Reschedule() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Reschedule")
}

// Reschedule indicates an expected call of Reschedule.
func (mr *MockExecutableTaskMockRecorder) Reschedule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reschedule", reflect.TypeOf((*MockExecutableTask)(nil).Reschedule))
}

// Resend mocks base method.
func (m *MockExecutableTask) Resend(ctx context.Context, remoteCluster string, retryErr *serviceerror.RetryReplication) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resend", ctx, remoteCluster, retryErr)
	ret0, _ := ret[0].(error)
	return ret0
}

// Resend indicates an expected call of Resend.
func (mr *MockExecutableTaskMockRecorder) Resend(ctx, remoteCluster, retryErr interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resend", reflect.TypeOf((*MockExecutableTask)(nil).Resend), ctx, remoteCluster, retryErr)
}

// RetryPolicy mocks base method.
func (m *MockExecutableTask) RetryPolicy() backoff.RetryPolicy {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RetryPolicy")
	ret0, _ := ret[0].(backoff.RetryPolicy)
	return ret0
}

// RetryPolicy indicates an expected call of RetryPolicy.
func (mr *MockExecutableTaskMockRecorder) RetryPolicy() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RetryPolicy", reflect.TypeOf((*MockExecutableTask)(nil).RetryPolicy))
}

// State mocks base method.
func (m *MockExecutableTask) State() tasks.State {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "State")
	ret0, _ := ret[0].(tasks.State)
	return ret0
}

// State indicates an expected call of State.
func (mr *MockExecutableTaskMockRecorder) State() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "State", reflect.TypeOf((*MockExecutableTask)(nil).State))
}

// TaskCreationTime mocks base method.
func (m *MockExecutableTask) TaskCreationTime() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TaskCreationTime")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// TaskCreationTime indicates an expected call of TaskCreationTime.
func (mr *MockExecutableTaskMockRecorder) TaskCreationTime() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TaskCreationTime", reflect.TypeOf((*MockExecutableTask)(nil).TaskCreationTime))
}

// TaskID mocks base method.
func (m *MockExecutableTask) TaskID() int64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TaskID")
	ret0, _ := ret[0].(int64)
	return ret0
}

// TaskID indicates an expected call of TaskID.
func (mr *MockExecutableTaskMockRecorder) TaskID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TaskID", reflect.TypeOf((*MockExecutableTask)(nil).TaskID))
}