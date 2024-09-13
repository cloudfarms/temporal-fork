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
// Source: interface.go
//
// Generated by this command:
//
//	mockgen -copyright_file ../../LICENSE -package archiver -source interface.go -destination interface_mock.go
//

// Package archiver is a generated GoMock package.
package archiver

import (
	context "context"
	reflect "reflect"

	archiver "go.temporal.io/server/api/archiver/v1"
	searchattribute "go.temporal.io/server/common/searchattribute"
	gomock "go.uber.org/mock/gomock"
)

// MockHistoryArchiver is a mock of HistoryArchiver interface.
type MockHistoryArchiver struct {
	ctrl     *gomock.Controller
	recorder *MockHistoryArchiverMockRecorder
}

// MockHistoryArchiverMockRecorder is the mock recorder for MockHistoryArchiver.
type MockHistoryArchiverMockRecorder struct {
	mock *MockHistoryArchiver
}

// NewMockHistoryArchiver creates a new mock instance.
func NewMockHistoryArchiver(ctrl *gomock.Controller) *MockHistoryArchiver {
	mock := &MockHistoryArchiver{ctrl: ctrl}
	mock.recorder = &MockHistoryArchiverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHistoryArchiver) EXPECT() *MockHistoryArchiverMockRecorder {
	return m.recorder
}

// Archive mocks base method.
func (m *MockHistoryArchiver) Archive(ctx context.Context, uri URI, request *ArchiveHistoryRequest, opts ...ArchiveOption) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, uri, request}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Archive", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Archive indicates an expected call of Archive.
func (mr *MockHistoryArchiverMockRecorder) Archive(ctx, uri, request any, opts ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, uri, request}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Archive", reflect.TypeOf((*MockHistoryArchiver)(nil).Archive), varargs...)
}

// Get mocks base method.
func (m *MockHistoryArchiver) Get(ctx context.Context, url URI, request *GetHistoryRequest) (*GetHistoryResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, url, request)
	ret0, _ := ret[0].(*GetHistoryResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockHistoryArchiverMockRecorder) Get(ctx, url, request any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockHistoryArchiver)(nil).Get), ctx, url, request)
}

// ValidateURI mocks base method.
func (m *MockHistoryArchiver) ValidateURI(uri URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateURI", uri)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateURI indicates an expected call of ValidateURI.
func (mr *MockHistoryArchiverMockRecorder) ValidateURI(uri any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateURI", reflect.TypeOf((*MockHistoryArchiver)(nil).ValidateURI), uri)
}

// MockVisibilityArchiver is a mock of VisibilityArchiver interface.
type MockVisibilityArchiver struct {
	ctrl     *gomock.Controller
	recorder *MockVisibilityArchiverMockRecorder
}

// MockVisibilityArchiverMockRecorder is the mock recorder for MockVisibilityArchiver.
type MockVisibilityArchiverMockRecorder struct {
	mock *MockVisibilityArchiver
}

// NewMockVisibilityArchiver creates a new mock instance.
func NewMockVisibilityArchiver(ctrl *gomock.Controller) *MockVisibilityArchiver {
	mock := &MockVisibilityArchiver{ctrl: ctrl}
	mock.recorder = &MockVisibilityArchiverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVisibilityArchiver) EXPECT() *MockVisibilityArchiverMockRecorder {
	return m.recorder
}

// Archive mocks base method.
func (m *MockVisibilityArchiver) Archive(ctx context.Context, uri URI, request *archiver.VisibilityRecord, opts ...ArchiveOption) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, uri, request}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Archive", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Archive indicates an expected call of Archive.
func (mr *MockVisibilityArchiverMockRecorder) Archive(ctx, uri, request any, opts ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, uri, request}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Archive", reflect.TypeOf((*MockVisibilityArchiver)(nil).Archive), varargs...)
}

// Query mocks base method.
func (m *MockVisibilityArchiver) Query(ctx context.Context, uri URI, request *QueryVisibilityRequest, saTypeMap searchattribute.NameTypeMap) (*QueryVisibilityResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Query", ctx, uri, request, saTypeMap)
	ret0, _ := ret[0].(*QueryVisibilityResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query.
func (mr *MockVisibilityArchiverMockRecorder) Query(ctx, uri, request, saTypeMap any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*MockVisibilityArchiver)(nil).Query), ctx, uri, request, saTypeMap)
}

// ValidateURI mocks base method.
func (m *MockVisibilityArchiver) ValidateURI(uri URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateURI", uri)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateURI indicates an expected call of ValidateURI.
func (mr *MockVisibilityArchiverMockRecorder) ValidateURI(uri any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateURI", reflect.TypeOf((*MockVisibilityArchiver)(nil).ValidateURI), uri)
}
