/**
 * Alerts List Page
 */

import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '@/lib/api'
import type { Alert, AlertFilters } from '@/types'
import { Search, Filter, Eye, ArrowUpDown } from 'lucide-react'

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

export const Alerts: React.FC = () => {
  const [filters, setFilters] = useState<AlertFilters>({
    page: 1,
    page_size: 20,
    sort_by: 'created_at',
    sort_order: 'desc',
  })

  const [searchTerm, setSearchTerm] = useState('')

  // Fetch alerts
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => api.alerts.getAlerts(filters),
  })

  const alerts = data?.data || []
  const total = data?.total || 0
  const totalPages = data?.total_pages || 0

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setFilters({ ...filters, search: searchTerm, page: 1 })
  }

  const handleSort = (field: string) => {
    if (filters.sort_by === field) {
      setFilters({
        ...filters,
        sort_order: filters.sort_order === 'asc' ? 'desc' : 'asc',
      })
    } else {
      setFilters({
        ...filters,
        sort_by: field,
        sort_order: 'desc',
      })
    }
  }

  const handlePageChange = (newPage: number) => {
    setFilters({ ...filters, page: newPage })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
          <p className="text-sm text-gray-600 mt-1">
            Total: {total.toLocaleString()} alerts
          </p>
        </div>
        <button className="btn btn-primary">
          Create Alert
        </button>
      </div>

      {/* Search and Filters */}
      <div className="card">
        <div className="card-body">
          <div className="flex flex-col md:flex-row gap-4">
            {/* Search */}
            <form onSubmit={handleSearch} className="flex-1 flex gap-2">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search alerts by ID, title, or IP..."
                  className="input pl-10"
                />
              </div>
              <button type="submit" className="btn btn-primary">
                Search
              </button>
            </form>

            {/* Filters */}
            <button className="btn btn-outline flex items-center gap-2">
              <Filter className="w-4 h-4" />
              Filters
            </button>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="spinner"></div>
            </div>
          ) : alerts.length === 0 ? (
            <div className="text-center py-12">
              <AlertTriangle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">No alerts found</p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th
                    className="cursor-pointer hover:bg-gray-100"
                    onClick={() => handleSort('alert_id')}
                  >
                    <div className="flex items-center gap-2">
                      ID
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:bg-gray-100"
                    onClick={() => handleSort('title')}
                  >
                    <div className="flex items-center gap-2">
                      Title
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Type</th>
                  <th
                    className="cursor-pointer hover:bg-gray-100"
                    onClick={() => handleSort('created_at')}
                  >
                    <div className="flex items-center gap-2">
                      Created
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td className="font-mono text-sm">{alert.alert_id}</td>
                    <td>
                      <div className="max-w-xs truncate" title={alert.title}>
                        {alert.title}
                      </div>
                    </td>
                    <td>
                      <span className={severityColors[alert.severity]}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${statusColors[alert.status]}`}>
                        {alert.status.replace('_', ' ').toUpperCase()}
                      </span>
                    </td>
                    <td className="capitalize">{alert.alert_type.replace('_', ' ')}</td>
                    <td className="text-sm text-gray-600">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td>
                      <Link
                        to={`/alerts/${alert.alert_id}`}
                        className="text-primary-600 hover:text-primary-700"
                      >
                        <Eye className="w-5 h-5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="card-footer flex items-center justify-between">
            <div className="text-sm text-gray-600">
              Page {filters.page} of {totalPages} ({total.toLocaleString()} total)
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => handlePageChange(filters.page! - 1)}
                disabled={filters.page === 1}
                className="btn btn-outline disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => handlePageChange(filters.page! + 1)}
                disabled={filters.page === totalPages}
                className="btn btn-outline disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
