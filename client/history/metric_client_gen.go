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

// Code generated by cmd/tools/genrpcwrappers. DO NOT EDIT.

package history

import (
	"context"

	"go.temporal.io/server/api/historyservice/v1"
	"google.golang.org/grpc"
)

func (c *metricClient) AddTasks(
	ctx context.Context,
	request *historyservice.AddTasksRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.AddTasksResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientAddTasks")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.AddTasks(ctx, request, opts...)
}

func (c *metricClient) CloseShard(
	ctx context.Context,
	request *historyservice.CloseShardRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.CloseShardResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientCloseShard")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.CloseShard(ctx, request, opts...)
}

func (c *metricClient) CompleteNexusOperation(
	ctx context.Context,
	request *historyservice.CompleteNexusOperationRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.CompleteNexusOperationResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientCompleteNexusOperation")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.CompleteNexusOperation(ctx, request, opts...)
}

func (c *metricClient) DeepHealthCheck(
	ctx context.Context,
	request *historyservice.DeepHealthCheckRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DeepHealthCheckResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDeepHealthCheck")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DeepHealthCheck(ctx, request, opts...)
}

func (c *metricClient) DeleteDLQTasks(
	ctx context.Context,
	request *historyservice.DeleteDLQTasksRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DeleteDLQTasksResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDeleteDLQTasks")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DeleteDLQTasks(ctx, request, opts...)
}

func (c *metricClient) DeleteWorkflowExecution(
	ctx context.Context,
	request *historyservice.DeleteWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DeleteWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDeleteWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DeleteWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) DeleteWorkflowVisibilityRecord(
	ctx context.Context,
	request *historyservice.DeleteWorkflowVisibilityRecordRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DeleteWorkflowVisibilityRecordResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDeleteWorkflowVisibilityRecord")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DeleteWorkflowVisibilityRecord(ctx, request, opts...)
}

func (c *metricClient) DescribeHistoryHost(
	ctx context.Context,
	request *historyservice.DescribeHistoryHostRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DescribeHistoryHostResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDescribeHistoryHost")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DescribeHistoryHost(ctx, request, opts...)
}

func (c *metricClient) DescribeMutableState(
	ctx context.Context,
	request *historyservice.DescribeMutableStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DescribeMutableStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDescribeMutableState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DescribeMutableState(ctx, request, opts...)
}

func (c *metricClient) DescribeWorkflowExecution(
	ctx context.Context,
	request *historyservice.DescribeWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.DescribeWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientDescribeWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.DescribeWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) ExecuteMultiOperation(
	ctx context.Context,
	request *historyservice.ExecuteMultiOperationRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ExecuteMultiOperationResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientExecuteMultiOperation")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ExecuteMultiOperation(ctx, request, opts...)
}

func (c *metricClient) ForceDeleteWorkflowExecution(
	ctx context.Context,
	request *historyservice.ForceDeleteWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ForceDeleteWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientForceDeleteWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ForceDeleteWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) GenerateLastHistoryReplicationTasks(
	ctx context.Context,
	request *historyservice.GenerateLastHistoryReplicationTasksRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GenerateLastHistoryReplicationTasksResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGenerateLastHistoryReplicationTasks")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GenerateLastHistoryReplicationTasks(ctx, request, opts...)
}

func (c *metricClient) GetDLQMessages(
	ctx context.Context,
	request *historyservice.GetDLQMessagesRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetDLQMessagesResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetDLQMessages")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetDLQMessages(ctx, request, opts...)
}

func (c *metricClient) GetDLQReplicationMessages(
	ctx context.Context,
	request *historyservice.GetDLQReplicationMessagesRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetDLQReplicationMessagesResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetDLQReplicationMessages")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetDLQReplicationMessages(ctx, request, opts...)
}

func (c *metricClient) GetDLQTasks(
	ctx context.Context,
	request *historyservice.GetDLQTasksRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetDLQTasksResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetDLQTasks")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetDLQTasks(ctx, request, opts...)
}

func (c *metricClient) GetMutableState(
	ctx context.Context,
	request *historyservice.GetMutableStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetMutableStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetMutableState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetMutableState(ctx, request, opts...)
}

func (c *metricClient) GetReplicationMessages(
	ctx context.Context,
	request *historyservice.GetReplicationMessagesRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetReplicationMessagesResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetReplicationMessages")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetReplicationMessages(ctx, request, opts...)
}

func (c *metricClient) GetReplicationStatus(
	ctx context.Context,
	request *historyservice.GetReplicationStatusRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetReplicationStatusResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetReplicationStatus")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetReplicationStatus(ctx, request, opts...)
}

func (c *metricClient) GetShard(
	ctx context.Context,
	request *historyservice.GetShardRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetShardResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetShard")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetShard(ctx, request, opts...)
}

func (c *metricClient) GetWorkflowExecutionHistory(
	ctx context.Context,
	request *historyservice.GetWorkflowExecutionHistoryRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetWorkflowExecutionHistoryResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetWorkflowExecutionHistory")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetWorkflowExecutionHistory(ctx, request, opts...)
}

func (c *metricClient) GetWorkflowExecutionHistoryReverse(
	ctx context.Context,
	request *historyservice.GetWorkflowExecutionHistoryReverseRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetWorkflowExecutionHistoryReverseResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetWorkflowExecutionHistoryReverse")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetWorkflowExecutionHistoryReverse(ctx, request, opts...)
}

func (c *metricClient) GetWorkflowExecutionRawHistory(
	ctx context.Context,
	request *historyservice.GetWorkflowExecutionRawHistoryRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.GetWorkflowExecutionRawHistoryResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetWorkflowExecutionRawHistory")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetWorkflowExecutionRawHistory(ctx, request, opts...)
}

func (c *metricClient) GetWorkflowExecutionRawHistoryV2(
	ctx context.Context,
	request *historyservice.GetWorkflowExecutionRawHistoryV2Request,
	opts ...grpc.CallOption,
) (_ *historyservice.GetWorkflowExecutionRawHistoryV2Response, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientGetWorkflowExecutionRawHistoryV2")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.GetWorkflowExecutionRawHistoryV2(ctx, request, opts...)
}

func (c *metricClient) ImportWorkflowExecution(
	ctx context.Context,
	request *historyservice.ImportWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ImportWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientImportWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ImportWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) InvokeStateMachineMethod(
	ctx context.Context,
	request *historyservice.InvokeStateMachineMethodRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.InvokeStateMachineMethodResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientInvokeStateMachineMethod")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.InvokeStateMachineMethod(ctx, request, opts...)
}

func (c *metricClient) IsActivityTaskValid(
	ctx context.Context,
	request *historyservice.IsActivityTaskValidRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.IsActivityTaskValidResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientIsActivityTaskValid")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.IsActivityTaskValid(ctx, request, opts...)
}

func (c *metricClient) IsWorkflowTaskValid(
	ctx context.Context,
	request *historyservice.IsWorkflowTaskValidRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.IsWorkflowTaskValidResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientIsWorkflowTaskValid")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.IsWorkflowTaskValid(ctx, request, opts...)
}

func (c *metricClient) ListQueues(
	ctx context.Context,
	request *historyservice.ListQueuesRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ListQueuesResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientListQueues")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ListQueues(ctx, request, opts...)
}

func (c *metricClient) ListTasks(
	ctx context.Context,
	request *historyservice.ListTasksRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ListTasksResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientListTasks")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ListTasks(ctx, request, opts...)
}

func (c *metricClient) MergeDLQMessages(
	ctx context.Context,
	request *historyservice.MergeDLQMessagesRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.MergeDLQMessagesResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientMergeDLQMessages")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.MergeDLQMessages(ctx, request, opts...)
}

func (c *metricClient) PollMutableState(
	ctx context.Context,
	request *historyservice.PollMutableStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.PollMutableStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientPollMutableState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.PollMutableState(ctx, request, opts...)
}

func (c *metricClient) PollWorkflowExecutionUpdate(
	ctx context.Context,
	request *historyservice.PollWorkflowExecutionUpdateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.PollWorkflowExecutionUpdateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientPollWorkflowExecutionUpdate")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.PollWorkflowExecutionUpdate(ctx, request, opts...)
}

func (c *metricClient) PurgeDLQMessages(
	ctx context.Context,
	request *historyservice.PurgeDLQMessagesRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.PurgeDLQMessagesResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientPurgeDLQMessages")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.PurgeDLQMessages(ctx, request, opts...)
}

func (c *metricClient) QueryWorkflow(
	ctx context.Context,
	request *historyservice.QueryWorkflowRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.QueryWorkflowResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientQueryWorkflow")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.QueryWorkflow(ctx, request, opts...)
}

func (c *metricClient) ReapplyEvents(
	ctx context.Context,
	request *historyservice.ReapplyEventsRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ReapplyEventsResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientReapplyEvents")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ReapplyEvents(ctx, request, opts...)
}

func (c *metricClient) RebuildMutableState(
	ctx context.Context,
	request *historyservice.RebuildMutableStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RebuildMutableStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRebuildMutableState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RebuildMutableState(ctx, request, opts...)
}

func (c *metricClient) RecordActivityTaskHeartbeat(
	ctx context.Context,
	request *historyservice.RecordActivityTaskHeartbeatRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RecordActivityTaskHeartbeatResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRecordActivityTaskHeartbeat")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RecordActivityTaskHeartbeat(ctx, request, opts...)
}

func (c *metricClient) RecordActivityTaskStarted(
	ctx context.Context,
	request *historyservice.RecordActivityTaskStartedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RecordActivityTaskStartedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRecordActivityTaskStarted")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RecordActivityTaskStarted(ctx, request, opts...)
}

func (c *metricClient) RecordChildExecutionCompleted(
	ctx context.Context,
	request *historyservice.RecordChildExecutionCompletedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RecordChildExecutionCompletedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRecordChildExecutionCompleted")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RecordChildExecutionCompleted(ctx, request, opts...)
}

func (c *metricClient) RecordWorkflowTaskStarted(
	ctx context.Context,
	request *historyservice.RecordWorkflowTaskStartedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RecordWorkflowTaskStartedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRecordWorkflowTaskStarted")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RecordWorkflowTaskStarted(ctx, request, opts...)
}

func (c *metricClient) RefreshWorkflowTasks(
	ctx context.Context,
	request *historyservice.RefreshWorkflowTasksRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RefreshWorkflowTasksResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRefreshWorkflowTasks")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RefreshWorkflowTasks(ctx, request, opts...)
}

func (c *metricClient) RemoveSignalMutableState(
	ctx context.Context,
	request *historyservice.RemoveSignalMutableStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RemoveSignalMutableStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRemoveSignalMutableState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RemoveSignalMutableState(ctx, request, opts...)
}

func (c *metricClient) RemoveTask(
	ctx context.Context,
	request *historyservice.RemoveTaskRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RemoveTaskResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRemoveTask")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RemoveTask(ctx, request, opts...)
}

func (c *metricClient) ReplicateEventsV2(
	ctx context.Context,
	request *historyservice.ReplicateEventsV2Request,
	opts ...grpc.CallOption,
) (_ *historyservice.ReplicateEventsV2Response, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientReplicateEventsV2")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ReplicateEventsV2(ctx, request, opts...)
}

func (c *metricClient) ReplicateWorkflowState(
	ctx context.Context,
	request *historyservice.ReplicateWorkflowStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ReplicateWorkflowStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientReplicateWorkflowState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ReplicateWorkflowState(ctx, request, opts...)
}

func (c *metricClient) RequestCancelWorkflowExecution(
	ctx context.Context,
	request *historyservice.RequestCancelWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RequestCancelWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRequestCancelWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RequestCancelWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) ResetStickyTaskQueue(
	ctx context.Context,
	request *historyservice.ResetStickyTaskQueueRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ResetStickyTaskQueueResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientResetStickyTaskQueue")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ResetStickyTaskQueue(ctx, request, opts...)
}

func (c *metricClient) ResetWorkflowExecution(
	ctx context.Context,
	request *historyservice.ResetWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ResetWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientResetWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ResetWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) RespondActivityTaskCanceled(
	ctx context.Context,
	request *historyservice.RespondActivityTaskCanceledRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RespondActivityTaskCanceledResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRespondActivityTaskCanceled")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RespondActivityTaskCanceled(ctx, request, opts...)
}

func (c *metricClient) RespondActivityTaskCompleted(
	ctx context.Context,
	request *historyservice.RespondActivityTaskCompletedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RespondActivityTaskCompletedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRespondActivityTaskCompleted")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RespondActivityTaskCompleted(ctx, request, opts...)
}

func (c *metricClient) RespondActivityTaskFailed(
	ctx context.Context,
	request *historyservice.RespondActivityTaskFailedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RespondActivityTaskFailedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRespondActivityTaskFailed")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RespondActivityTaskFailed(ctx, request, opts...)
}

func (c *metricClient) RespondWorkflowTaskCompleted(
	ctx context.Context,
	request *historyservice.RespondWorkflowTaskCompletedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RespondWorkflowTaskCompletedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRespondWorkflowTaskCompleted")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RespondWorkflowTaskCompleted(ctx, request, opts...)
}

func (c *metricClient) RespondWorkflowTaskFailed(
	ctx context.Context,
	request *historyservice.RespondWorkflowTaskFailedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.RespondWorkflowTaskFailedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientRespondWorkflowTaskFailed")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.RespondWorkflowTaskFailed(ctx, request, opts...)
}

func (c *metricClient) ScheduleWorkflowTask(
	ctx context.Context,
	request *historyservice.ScheduleWorkflowTaskRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.ScheduleWorkflowTaskResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientScheduleWorkflowTask")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.ScheduleWorkflowTask(ctx, request, opts...)
}

func (c *metricClient) SignalWithStartWorkflowExecution(
	ctx context.Context,
	request *historyservice.SignalWithStartWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.SignalWithStartWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientSignalWithStartWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.SignalWithStartWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) SignalWorkflowExecution(
	ctx context.Context,
	request *historyservice.SignalWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.SignalWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientSignalWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.SignalWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) StartWorkflowExecution(
	ctx context.Context,
	request *historyservice.StartWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.StartWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientStartWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.StartWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) SyncActivity(
	ctx context.Context,
	request *historyservice.SyncActivityRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.SyncActivityResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientSyncActivity")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.SyncActivity(ctx, request, opts...)
}

func (c *metricClient) SyncShardStatus(
	ctx context.Context,
	request *historyservice.SyncShardStatusRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.SyncShardStatusResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientSyncShardStatus")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.SyncShardStatus(ctx, request, opts...)
}

func (c *metricClient) SyncWorkflowState(
	ctx context.Context,
	request *historyservice.SyncWorkflowStateRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.SyncWorkflowStateResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientSyncWorkflowState")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.SyncWorkflowState(ctx, request, opts...)
}

func (c *metricClient) TerminateWorkflowExecution(
	ctx context.Context,
	request *historyservice.TerminateWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.TerminateWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientTerminateWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.TerminateWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) UpdateActivityOptions(
	ctx context.Context,
	request *historyservice.UpdateActivityOptionsRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.UpdateActivityOptionsResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientUpdateActivityOptions")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.UpdateActivityOptions(ctx, request, opts...)
}

func (c *metricClient) UpdateWorkflowExecution(
	ctx context.Context,
	request *historyservice.UpdateWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.UpdateWorkflowExecutionResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientUpdateWorkflowExecution")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.UpdateWorkflowExecution(ctx, request, opts...)
}

func (c *metricClient) VerifyChildExecutionCompletionRecorded(
	ctx context.Context,
	request *historyservice.VerifyChildExecutionCompletionRecordedRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.VerifyChildExecutionCompletionRecordedResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientVerifyChildExecutionCompletionRecorded")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.VerifyChildExecutionCompletionRecorded(ctx, request, opts...)
}

func (c *metricClient) VerifyFirstWorkflowTaskScheduled(
	ctx context.Context,
	request *historyservice.VerifyFirstWorkflowTaskScheduledRequest,
	opts ...grpc.CallOption,
) (_ *historyservice.VerifyFirstWorkflowTaskScheduledResponse, retError error) {

	metricsHandler, startTime := c.startMetricsRecording(ctx, "HistoryClientVerifyFirstWorkflowTaskScheduled")
	defer func() {
		c.finishMetricsRecording(metricsHandler, startTime, retError)
	}()

	return c.client.VerifyFirstWorkflowTaskScheduled(ctx, request, opts...)
}
