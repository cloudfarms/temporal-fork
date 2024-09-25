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

// Code generated by cmd/tools/genrpcserverinterceptors. DO NOT EDIT.

package logtags

import (
	"go.temporal.io/server/api/adminservice/v1"
	"go.temporal.io/server/common/log/tag"
)

func (wt *WorkflowTags) extractFromAdminServiceServerRequest(req any) []tag.Tag {
	switch r := req.(type) {
	case *adminservice.AddOrUpdateRemoteClusterRequest:
		return nil
	case *adminservice.AddSearchAttributesRequest:
		return nil
	case *adminservice.AddTasksRequest:
		return nil
	case *adminservice.CancelDLQJobRequest:
		return nil
	case *adminservice.CloseShardRequest:
		return nil
	case *adminservice.DeepHealthCheckRequest:
		return nil
	case *adminservice.DeleteWorkflowExecutionRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.DescribeClusterRequest:
		return nil
	case *adminservice.DescribeDLQJobRequest:
		return nil
	case *adminservice.DescribeHistoryHostRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetWorkflowExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetWorkflowExecution().GetRunId()),
		}
	case *adminservice.DescribeMutableStateRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.DescribeTaskQueuePartitionRequest:
		return nil
	case *adminservice.GenerateLastHistoryReplicationTasksRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.GetDLQMessagesRequest:
		return nil
	case *adminservice.GetDLQReplicationMessagesRequest:
		return nil
	case *adminservice.GetDLQTasksRequest:
		return nil
	case *adminservice.GetNamespaceRequest:
		return nil
	case *adminservice.GetNamespaceReplicationMessagesRequest:
		return nil
	case *adminservice.GetReplicationMessagesRequest:
		return nil
	case *adminservice.GetSearchAttributesRequest:
		return nil
	case *adminservice.GetShardRequest:
		return nil
	case *adminservice.GetTaskQueueTasksRequest:
		return nil
	case *adminservice.GetWorkflowExecutionRawHistoryRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.GetWorkflowExecutionRawHistoryV2Request:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.ImportWorkflowExecutionRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.ListClusterMembersRequest:
		return nil
	case *adminservice.ListClustersRequest:
		return nil
	case *adminservice.ListHistoryTasksRequest:
		return nil
	case *adminservice.ListQueuesRequest:
		return nil
	case *adminservice.MergeDLQMessagesRequest:
		return nil
	case *adminservice.MergeDLQTasksRequest:
		return nil
	case *adminservice.PurgeDLQMessagesRequest:
		return nil
	case *adminservice.PurgeDLQTasksRequest:
		return nil
	case *adminservice.ReapplyEventsRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetWorkflowExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetWorkflowExecution().GetRunId()),
		}
	case *adminservice.RebuildMutableStateRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.RefreshWorkflowTasksRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	case *adminservice.RemoveRemoteClusterRequest:
		return nil
	case *adminservice.RemoveSearchAttributesRequest:
		return nil
	case *adminservice.RemoveTaskRequest:
		return nil
	case *adminservice.ResendReplicationTasksRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetWorkflowId()),
			tag.WorkflowRunID(r.GetRunId()),
		}
	case *adminservice.SyncWorkflowStateRequest:
		return []tag.Tag{
			tag.WorkflowID(r.GetExecution().GetWorkflowId()),
			tag.WorkflowRunID(r.GetExecution().GetRunId()),
		}
	default:
		return nil
	}
}
