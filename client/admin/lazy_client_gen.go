
// Code generated by cmd/tools/rpcwrappers. DO NOT EDIT.

package admin

import (
	"context"

	"go.temporal.io/server/api/adminservice/v1"
	"google.golang.org/grpc"
)

func (c *lazyClient) AddOrUpdateRemoteCluster(
	ctx context.Context,
	request *adminservice.AddOrUpdateRemoteClusterRequest,
	opts ...grpc.CallOption,
) (*adminservice.AddOrUpdateRemoteClusterResponse, error) {
	var resp *adminservice.AddOrUpdateRemoteClusterResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.AddOrUpdateRemoteCluster(ctx, request, opts...)
}

func (c *lazyClient) AddSearchAttributes(
	ctx context.Context,
	request *adminservice.AddSearchAttributesRequest,
	opts ...grpc.CallOption,
) (*adminservice.AddSearchAttributesResponse, error) {
	var resp *adminservice.AddSearchAttributesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.AddSearchAttributes(ctx, request, opts...)
}

func (c *lazyClient) AddTasks(
	ctx context.Context,
	request *adminservice.AddTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.AddTasksResponse, error) {
	var resp *adminservice.AddTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.AddTasks(ctx, request, opts...)
}

func (c *lazyClient) CancelDLQJob(
	ctx context.Context,
	request *adminservice.CancelDLQJobRequest,
	opts ...grpc.CallOption,
) (*adminservice.CancelDLQJobResponse, error) {
	var resp *adminservice.CancelDLQJobResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.CancelDLQJob(ctx, request, opts...)
}

func (c *lazyClient) CloseShard(
	ctx context.Context,
	request *adminservice.CloseShardRequest,
	opts ...grpc.CallOption,
) (*adminservice.CloseShardResponse, error) {
	var resp *adminservice.CloseShardResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.CloseShard(ctx, request, opts...)
}

func (c *lazyClient) DeepHealthCheck(
	ctx context.Context,
	request *adminservice.DeepHealthCheckRequest,
	opts ...grpc.CallOption,
) (*adminservice.DeepHealthCheckResponse, error) {
	var resp *adminservice.DeepHealthCheckResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.DeepHealthCheck(ctx, request, opts...)
}

func (c *lazyClient) DeleteWorkflowExecution(
	ctx context.Context,
	request *adminservice.DeleteWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (*adminservice.DeleteWorkflowExecutionResponse, error) {
	var resp *adminservice.DeleteWorkflowExecutionResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.DeleteWorkflowExecution(ctx, request, opts...)
}

func (c *lazyClient) DescribeCluster(
	ctx context.Context,
	request *adminservice.DescribeClusterRequest,
	opts ...grpc.CallOption,
) (*adminservice.DescribeClusterResponse, error) {
	var resp *adminservice.DescribeClusterResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.DescribeCluster(ctx, request, opts...)
}

func (c *lazyClient) DescribeDLQJob(
	ctx context.Context,
	request *adminservice.DescribeDLQJobRequest,
	opts ...grpc.CallOption,
) (*adminservice.DescribeDLQJobResponse, error) {
	var resp *adminservice.DescribeDLQJobResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.DescribeDLQJob(ctx, request, opts...)
}

func (c *lazyClient) DescribeHistoryHost(
	ctx context.Context,
	request *adminservice.DescribeHistoryHostRequest,
	opts ...grpc.CallOption,
) (*adminservice.DescribeHistoryHostResponse, error) {
	var resp *adminservice.DescribeHistoryHostResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.DescribeHistoryHost(ctx, request, opts...)
}

func (c *lazyClient) DescribeMutableState(
	ctx context.Context,
	request *adminservice.DescribeMutableStateRequest,
	opts ...grpc.CallOption,
) (*adminservice.DescribeMutableStateResponse, error) {
	var resp *adminservice.DescribeMutableStateResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.DescribeMutableState(ctx, request, opts...)
}

func (c *lazyClient) GetDLQMessages(
	ctx context.Context,
	request *adminservice.GetDLQMessagesRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetDLQMessagesResponse, error) {
	var resp *adminservice.GetDLQMessagesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetDLQMessages(ctx, request, opts...)
}

func (c *lazyClient) GetDLQReplicationMessages(
	ctx context.Context,
	request *adminservice.GetDLQReplicationMessagesRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetDLQReplicationMessagesResponse, error) {
	var resp *adminservice.GetDLQReplicationMessagesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetDLQReplicationMessages(ctx, request, opts...)
}

func (c *lazyClient) GetDLQTasks(
	ctx context.Context,
	request *adminservice.GetDLQTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetDLQTasksResponse, error) {
	var resp *adminservice.GetDLQTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetDLQTasks(ctx, request, opts...)
}

func (c *lazyClient) GetNamespace(
	ctx context.Context,
	request *adminservice.GetNamespaceRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetNamespaceResponse, error) {
	var resp *adminservice.GetNamespaceResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetNamespace(ctx, request, opts...)
}

func (c *lazyClient) GetNamespaceReplicationMessages(
	ctx context.Context,
	request *adminservice.GetNamespaceReplicationMessagesRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetNamespaceReplicationMessagesResponse, error) {
	var resp *adminservice.GetNamespaceReplicationMessagesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetNamespaceReplicationMessages(ctx, request, opts...)
}

func (c *lazyClient) GetReplicationMessages(
	ctx context.Context,
	request *adminservice.GetReplicationMessagesRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetReplicationMessagesResponse, error) {
	var resp *adminservice.GetReplicationMessagesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetReplicationMessages(ctx, request, opts...)
}

func (c *lazyClient) GetSearchAttributes(
	ctx context.Context,
	request *adminservice.GetSearchAttributesRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetSearchAttributesResponse, error) {
	var resp *adminservice.GetSearchAttributesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetSearchAttributes(ctx, request, opts...)
}

func (c *lazyClient) GetShard(
	ctx context.Context,
	request *adminservice.GetShardRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetShardResponse, error) {
	var resp *adminservice.GetShardResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetShard(ctx, request, opts...)
}

func (c *lazyClient) GetTaskQueueTasks(
	ctx context.Context,
	request *adminservice.GetTaskQueueTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetTaskQueueTasksResponse, error) {
	var resp *adminservice.GetTaskQueueTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetTaskQueueTasks(ctx, request, opts...)
}

func (c *lazyClient) GetWorkflowExecutionRawHistory(
	ctx context.Context,
	request *adminservice.GetWorkflowExecutionRawHistoryRequest,
	opts ...grpc.CallOption,
) (*adminservice.GetWorkflowExecutionRawHistoryResponse, error) {
	var resp *adminservice.GetWorkflowExecutionRawHistoryResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetWorkflowExecutionRawHistory(ctx, request, opts...)
}

func (c *lazyClient) GetWorkflowExecutionRawHistoryV2(
	ctx context.Context,
	request *adminservice.GetWorkflowExecutionRawHistoryV2Request,
	opts ...grpc.CallOption,
) (*adminservice.GetWorkflowExecutionRawHistoryV2Response, error) {
	var resp *adminservice.GetWorkflowExecutionRawHistoryV2Response
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.GetWorkflowExecutionRawHistoryV2(ctx, request, opts...)
}

func (c *lazyClient) ImportWorkflowExecution(
	ctx context.Context,
	request *adminservice.ImportWorkflowExecutionRequest,
	opts ...grpc.CallOption,
) (*adminservice.ImportWorkflowExecutionResponse, error) {
	var resp *adminservice.ImportWorkflowExecutionResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ImportWorkflowExecution(ctx, request, opts...)
}

func (c *lazyClient) ListClusterMembers(
	ctx context.Context,
	request *adminservice.ListClusterMembersRequest,
	opts ...grpc.CallOption,
) (*adminservice.ListClusterMembersResponse, error) {
	var resp *adminservice.ListClusterMembersResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ListClusterMembers(ctx, request, opts...)
}

func (c *lazyClient) ListClusters(
	ctx context.Context,
	request *adminservice.ListClustersRequest,
	opts ...grpc.CallOption,
) (*adminservice.ListClustersResponse, error) {
	var resp *adminservice.ListClustersResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ListClusters(ctx, request, opts...)
}

func (c *lazyClient) ListHistoryTasks(
	ctx context.Context,
	request *adminservice.ListHistoryTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.ListHistoryTasksResponse, error) {
	var resp *adminservice.ListHistoryTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ListHistoryTasks(ctx, request, opts...)
}

func (c *lazyClient) ListQueues(
	ctx context.Context,
	request *adminservice.ListQueuesRequest,
	opts ...grpc.CallOption,
) (*adminservice.ListQueuesResponse, error) {
	var resp *adminservice.ListQueuesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ListQueues(ctx, request, opts...)
}

func (c *lazyClient) MergeDLQMessages(
	ctx context.Context,
	request *adminservice.MergeDLQMessagesRequest,
	opts ...grpc.CallOption,
) (*adminservice.MergeDLQMessagesResponse, error) {
	var resp *adminservice.MergeDLQMessagesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.MergeDLQMessages(ctx, request, opts...)
}

func (c *lazyClient) MergeDLQTasks(
	ctx context.Context,
	request *adminservice.MergeDLQTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.MergeDLQTasksResponse, error) {
	var resp *adminservice.MergeDLQTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.MergeDLQTasks(ctx, request, opts...)
}

func (c *lazyClient) PurgeDLQMessages(
	ctx context.Context,
	request *adminservice.PurgeDLQMessagesRequest,
	opts ...grpc.CallOption,
) (*adminservice.PurgeDLQMessagesResponse, error) {
	var resp *adminservice.PurgeDLQMessagesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.PurgeDLQMessages(ctx, request, opts...)
}

func (c *lazyClient) PurgeDLQTasks(
	ctx context.Context,
	request *adminservice.PurgeDLQTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.PurgeDLQTasksResponse, error) {
	var resp *adminservice.PurgeDLQTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.PurgeDLQTasks(ctx, request, opts...)
}

func (c *lazyClient) ReapplyEvents(
	ctx context.Context,
	request *adminservice.ReapplyEventsRequest,
	opts ...grpc.CallOption,
) (*adminservice.ReapplyEventsResponse, error) {
	var resp *adminservice.ReapplyEventsResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ReapplyEvents(ctx, request, opts...)
}

func (c *lazyClient) RebuildMutableState(
	ctx context.Context,
	request *adminservice.RebuildMutableStateRequest,
	opts ...grpc.CallOption,
) (*adminservice.RebuildMutableStateResponse, error) {
	var resp *adminservice.RebuildMutableStateResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.RebuildMutableState(ctx, request, opts...)
}

func (c *lazyClient) RefreshWorkflowTasks(
	ctx context.Context,
	request *adminservice.RefreshWorkflowTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.RefreshWorkflowTasksResponse, error) {
	var resp *adminservice.RefreshWorkflowTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.RefreshWorkflowTasks(ctx, request, opts...)
}

func (c *lazyClient) RemoveRemoteCluster(
	ctx context.Context,
	request *adminservice.RemoveRemoteClusterRequest,
	opts ...grpc.CallOption,
) (*adminservice.RemoveRemoteClusterResponse, error) {
	var resp *adminservice.RemoveRemoteClusterResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.RemoveRemoteCluster(ctx, request, opts...)
}

func (c *lazyClient) RemoveSearchAttributes(
	ctx context.Context,
	request *adminservice.RemoveSearchAttributesRequest,
	opts ...grpc.CallOption,
) (*adminservice.RemoveSearchAttributesResponse, error) {
	var resp *adminservice.RemoveSearchAttributesResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.RemoveSearchAttributes(ctx, request, opts...)
}

func (c *lazyClient) RemoveTask(
	ctx context.Context,
	request *adminservice.RemoveTaskRequest,
	opts ...grpc.CallOption,
) (*adminservice.RemoveTaskResponse, error) {
	var resp *adminservice.RemoveTaskResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.RemoveTask(ctx, request, opts...)
}

func (c *lazyClient) ResendReplicationTasks(
	ctx context.Context,
	request *adminservice.ResendReplicationTasksRequest,
	opts ...grpc.CallOption,
) (*adminservice.ResendReplicationTasksResponse, error) {
	var resp *adminservice.ResendReplicationTasksResponse
	client, err := c.clientProvider.GetAdminClient()
	if err != nil {
		return resp, err
	}

	return client.ResendReplicationTasks(ctx, request, opts...)
}
