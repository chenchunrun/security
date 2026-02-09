/**
 * Alert Detail Page - Full alert information and actions
 */

import React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { api } from '@/lib/api'
import {
  ArrowLeft,
  Clock,
  Server,
  Globe,
  FileText,
  CheckCircle,
  XCircle,
  AlertCircle,
  Activity,
} from 'lucide-react'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

const statusColors = {
  pending: 'bg-gray-100 text-gray-800',
  analyzing: 'bg-blue-100 text-blue-800',
  triaged: 'bg-purple-100 text-purple-800',
  in_progress: 'bg-yellow-100 text-yellow-800',
  resolved: 'bg-green-100 text-green-800',
  closed: 'bg-gray-100 text-gray-800',
  false_positive: 'bg-red-100 text-red-800',
}

const statusLabels = {
  pending: 'Pending',
  analyzing: 'Analyzing',
  triaged: 'Triaged',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  closed: 'Closed',
  false_positive: 'False Positive',
}

export const AlertDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const queryClient = useQueryClient()

  // Fetch alert details
  const { data: alert, isLoading, error } = useQuery({
    queryKey: ['alert', id],
    queryFn: () => api.alerts.getAlert(id!),
    enabled: !!id,
  })

  // Update status mutation
  const updateStatusMutation = useMutation({
    mutationFn: ({ status, note }: { status: string; note?: string }) =>
      api.alerts.updateAlertStatus(id!, status, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert', id] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const handleStatusChange = (status: string) => {
    if (window.confirm(`Change alert status to ${status.replace('_', ' ').toUpperCase()}?`)) {
      updateStatusMutation.mutate({ status })
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div className="card">
          <div className="card-body text-center py-12">
            <AlertCircle className="w-12 h-12 text-danger-500 mx-auto mb-4" />
            <p className="text-gray-900 font-medium mb-2">Failed to load alert</p>
            <p className="text-sm text-gray-600 mb-4">
              {error instanceof Error ? error.message : 'Unknown error'}
            </p>
            <Link to="/alerts" className="btn btn-primary mt-4">
              Back to Alerts
            </Link>
          </div>
        </div>
      </div>
    )
  }

  if (!alert) {
    return (
      <div className="space-y-6">
        <div className="card">
          <div className="card-body text-center py-12">
            <AlertCircle className="w-12 h-12 text-danger-500 mx-auto mb-4" />
            <p className="text-gray-600">Alert not found</p>
            <p className="text-sm text-gray-500">Alert ID: {id}</p>
            <Link to="/alerts" className="btn btn-primary mt-4">
              Back to Alerts
            </Link>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            to="/alerts"
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-gray-600" />
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-gray-900">{alert.alert_id}</h1>
              <span className={severityColors[alert.severity]}>
                {alert.severity.toUpperCase()}
              </span>
            </div>
            <p className="text-sm text-gray-600 mt-1">
              Created {new Date(alert.created_at).toLocaleString()}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleStatusChange('resolved')}
            className="btn btn-success flex items-center gap-2"
            disabled={updateStatusMutation.isPending}
          >
            <CheckCircle className="w-4 h-4" />
            Mark Resolved
          </button>
          <button
            onClick={() => handleStatusChange('false_positive')}
            className="btn btn-outline flex items-center gap-2"
            disabled={updateStatusMutation.isPending}
          >
            <XCircle className="w-4 h-4" />
            False Positive
          </button>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Alert Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* Basic Information */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900">Basic Information</h2>
            </div>
            <div className="card-body space-y-4">
              <div>
                <label className="text-sm font-medium text-gray-600">Title</label>
                <p className="text-gray-900 mt-1">{alert.title}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Description</label>
                <p className="text-gray-900 mt-1 whitespace-pre-wrap">{alert.description || 'No description'}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-600">Alert Type</label>
                  <p className="text-gray-900 mt-1 capitalize">{alert.alert_type.replace('_', ' ')}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600">Status</label>
                  <span className={`badge ${statusColors[alert.status]} mt-1 inline-block`}>
                    {statusLabels[alert.status] || alert.status.toUpperCase()}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Network Information */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <Globe className="w-5 h-5" />
                Network Information
              </h2>
            </div>
            <div className="card-body">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-600">Source IP</label>
                  <p className="text-gray-900 mt-1 font-mono">{alert.source_ip || 'N/A'}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600">Target IP</label>
                  <p className="text-gray-900 mt-1 font-mono">{alert.destination_ip || alert.target_ip || 'N/A'}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Entity Information */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <Server className="w-5 h-5" />
                Entity Information
              </h2>
            </div>
            <div className="card-body">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-600">Asset ID</label>
                  <p className="text-gray-900 mt-1 font-mono">{alert.asset_id || 'N/A'}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600">User ID</label>
                  <p className="text-gray-900 mt-1 font-mono">{alert.user_id || 'N/A'}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600">File Hash</label>
                  <p className="text-gray-900 mt-1 font-mono text-sm break-all">{alert.file_hash || 'N/A'}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600">URL</label>
                  <p className="text-gray-900 mt-1 text-sm break-all">{alert.url || 'N/A'}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <Clock className="w-5 h-5" />
                Timeline
              </h2>
            </div>
            <div className="card-body">
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 bg-primary-500 rounded-full mt-2"></div>
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900">Alert Created</p>
                    <p className="text-xs text-gray-600">{new Date(alert.created_at).toLocaleString()}</p>
                  </div>
                </div>
                {alert.updated_at !== alert.created_at && (
                  <div className="flex items-start gap-3">
                    <div className="w-2 h-2 bg-warning-500 rounded-full mt-2"></div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900">Last Updated</p>
                      <p className="text-xs text-gray-600">{new Date(alert.updated_at).toLocaleString()}</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column - Quick Actions */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900">Quick Actions</h2>
            </div>
            <div className="card-body space-y-3">
              <button
                onClick={() => handleStatusChange('in_progress')}
                className="w-full btn btn-outline flex items-center justify-center gap-2"
                disabled={updateStatusMutation.isPending}
              >
                <Activity className="w-4 h-4" />
                Start Investigation
              </button>
              <button
                onClick={() => handleStatusChange('resolved')}
                className="w-full btn btn-success flex items-center justify-center gap-2"
                disabled={updateStatusMutation.isPending}
              >
                <CheckCircle className="w-4 h-4" />
                Mark Resolved
              </button>
              <button
                onClick={() => handleStatusChange('false_positive')}
                className="w-full btn btn-outline flex items-center justify-center gap-2 text-danger-600 border-danger-300 hover:bg-danger-50"
                disabled={updateStatusMutation.isPending}
              >
                <XCircle className="w-4 h-4" />
                Mark False Positive
              </button>
            </div>
          </div>

          {/* Status History */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900">Current Status</h2>
            </div>
            <div className="card-body">
              <div className="text-center py-4">
                <span className={`badge ${statusColors[alert.status]} text-lg px-4 py-2`}>
                  {statusLabels[alert.status] || alert.status.toUpperCase()}
                </span>
                <p className="text-sm text-gray-600 mt-2">
                  {alert.status === 'pending' && 'Waiting for investigation'}
                  {alert.status === 'analyzing' && 'AI analysis in progress'}
                  {alert.status === 'in_progress' && 'Under investigation'}
                  {alert.status === 'resolved' && 'Successfully resolved'}
                  {alert.status === 'false_positive' && 'Marked as false positive'}
                </p>
              </div>
            </div>
          </div>

          {/* Raw Data */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Raw Data
              </h2>
            </div>
            <div className="card-body">
              <pre className="bg-gray-50 p-4 rounded-lg overflow-x-auto text-xs">
                {JSON.stringify(alert, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
