import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { RefreshCw, Activity, Database, Cpu, MemoryStick } from 'lucide-react';

interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  memory_used_mb: number;
  timestamp: string;
}

interface PerformanceMetrics {
  active_requests: number;
  completed_requests: number;
  max_concurrent_requests: number;
  avg_response_time_seconds: number;
  error_rate: number;
  throughput_per_minute: number;
  system_metrics: SystemMetrics | null;
}

interface CacheStats {
  cache_size: number;
  max_size: number;
  hits: number;
  misses: number;
  hit_rate: number;
  estimated_memory_mb: number;
}

interface DashboardData {
  timestamp: string;
  health: {
    status: 'healthy' | 'degraded' | 'error';
    issues: Array<{
      type: string;
      message: string;
      severity: 'warning' | 'error';
    }>;
  };
  current_metrics: PerformanceMetrics;
  cache_stats: CacheStats;
  llm_status: {
    primary_provider: string;
    fallback_provider: string;
    providers_available: string[];
  };
}

const MonitoringDashboard: React.FC = () => {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const response = await fetch('/api/monitoring/metrics/dashboard');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      setDashboardData(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const handleRefresh = () => {
    setLoading(true);
    fetchDashboardData();
  };

  const handleClearCache = async () => {
    try {
      const response = await fetch('/api/monitoring/cache/clear', { method: 'POST' });
      if (response.ok) {
        fetchDashboardData(); // Refresh data after clearing cache
      }
    } catch (err) {
      console.error('Failed to clear cache:', err);
    }
  };

  const getHealthBadgeColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'bg-green-500';
      case 'degraded': return 'bg-yellow-500';
      case 'error': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (loading && !dashboardData) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="animate-spin h-8 w-8 text-blue-500" />
        <span className="ml-2">Loading dashboard...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
        <h3 className="text-red-800 font-medium">Error Loading Dashboard</h3>
        <p className="text-red-600 mt-1">{error}</p>
        <Button onClick={handleRefresh} className="mt-2" variant="outline" size="sm">
          <RefreshCw className="h-4 w-4 mr-2" />
          Retry
        </Button>
      </div>
    );
  }

  if (!dashboardData) return null;

  const { health, current_metrics, cache_stats, llm_status } = dashboardData;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">System Monitoring</h1>
        <div className="flex items-center space-x-2">
          <Badge className={getHealthBadgeColor(health.status)}>
            {health.status.toUpperCase()}
          </Badge>
          <Button
            onClick={handleRefresh}
            variant="outline"
            size="sm"
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button
            onClick={() => setAutoRefresh(!autoRefresh)}
            variant={autoRefresh ? "default" : "outline"}
            size="sm"
          >
            <Activity className="h-4 w-4 mr-2" />
            Auto Refresh
          </Button>
        </div>
      </div>

      {/* Health Issues */}
      {health.issues.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h3 className="text-yellow-800 font-medium mb-2">System Issues</h3>
          <ul className="space-y-1">
            {health.issues.map((issue, index) => (
              <li key={index} className="text-yellow-700 text-sm">
                <Badge variant={issue.severity === 'error' ? 'destructive' : 'secondary'} className="mr-2">
                  {issue.severity}
                </Badge>
                {issue.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Requests */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{current_metrics.active_requests}</div>
            <p className="text-xs text-muted-foreground">
              Max: {current_metrics.max_concurrent_requests}
            </p>
          </CardContent>
        </Card>

        {/* Response Time */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Response Time</CardTitle>
            <RefreshCw className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(current_metrics.avg_response_time_seconds * 1000).toFixed(0)}ms
            </div>
            <p className="text-xs text-muted-foreground">
              Error Rate: {(current_metrics.error_rate * 100).toFixed(1)}%
            </p>
          </CardContent>
        </Card>

        {/* Throughput */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Throughput</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{current_metrics.throughput_per_minute}</div>
            <p className="text-xs text-muted-foreground">requests/minute</p>
          </CardContent>
        </Card>

        {/* Cache Hit Rate */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Cache Hit Rate</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{(cache_stats.hit_rate * 100).toFixed(1)}%</div>
            <p className="text-xs text-muted-foreground">
              {cache_stats.cache_size}/{cache_stats.max_size} entries
            </p>
          </CardContent>
        </Card>
      </div>

      {/* System Resources */}
      {current_metrics.system_metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">CPU Usage</CardTitle>
              <Cpu className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {current_metrics.system_metrics.cpu_percent.toFixed(1)}%
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div
                  className={`h-2 rounded-full ${
                    current_metrics.system_metrics.cpu_percent > 80 ? 'bg-red-500' :
                    current_metrics.system_metrics.cpu_percent > 60 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(current_metrics.system_metrics.cpu_percent, 100)}%` }}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Memory Usage</CardTitle>
              <MemoryStick className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {current_metrics.system_metrics.memory_percent.toFixed(1)}%
              </div>
              <p className="text-xs text-muted-foreground">
                {formatBytes(current_metrics.system_metrics.memory_used_mb * 1024 * 1024)} used
              </p>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div
                  className={`h-2 rounded-full ${
                    current_metrics.system_metrics.memory_percent > 85 ? 'bg-red-500' :
                    current_metrics.system_metrics.memory_percent > 70 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(current_metrics.system_metrics.memory_percent, 100)}%` }}
                />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Cache Management */}
      <Card>
        <CardHeader>
          <CardTitle>Cache Management</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div>
              <p className="text-sm text-muted-foreground">Cache Size</p>
              <p className="text-lg font-semibold">{cache_stats.cache_size}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Cache Hits</p>
              <p className="text-lg font-semibold">{cache_stats.hits}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Cache Misses</p>
              <p className="text-lg font-semibold">{cache_stats.misses}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Memory Usage</p>
              <p className="text-lg font-semibold">{cache_stats.estimated_memory_mb.toFixed(1)} MB</p>
            </div>
          </div>
          <Button onClick={handleClearCache} variant="outline" size="sm">
            <Database className="h-4 w-4 mr-2" />
            Clear Cache
          </Button>
        </CardContent>
      </Card>

      {/* LLM Status */}
      <Card>
        <CardHeader>
          <CardTitle>LLM Provider Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div>
              <span className="text-sm text-muted-foreground">Primary Provider: </span>
              <Badge variant="outline">{llm_status.primary_provider}</Badge>
            </div>
            <div>
              <span className="text-sm text-muted-foreground">Fallback Provider: </span>
              <Badge variant="outline">{llm_status.fallback_provider}</Badge>
            </div>
            <div>
              <span className="text-sm text-muted-foreground">Available Providers: </span>
              {llm_status.providers_available.map(provider => (
                <Badge key={provider} variant="secondary" className="mr-1">
                  {provider}
                </Badge>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Footer */}
      <div className="text-center text-sm text-muted-foreground">
        Last updated: {new Date(dashboardData.timestamp).toLocaleString()}
      </div>
    </div>
  );
};

export default MonitoringDashboard;