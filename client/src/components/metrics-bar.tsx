import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import type { UserRole } from "@/types";

interface MetricsBarProps {
  currentRole: UserRole;
}

export default function MetricsBar({ currentRole }: MetricsBarProps) {
  const { data: metrics, isLoading } = useQuery({
    queryKey: ["/api/metrics", currentRole],
    queryFn: () => api.getMetrics(currentRole)
  });

  if (isLoading) {
    return (
      <div className="bg-secondary/30 px-6 py-4 border-b border-border">
        <Skeleton className="h-4 w-48 mb-3" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  if (!metrics) return null;

  return (
    <div className="bg-secondary/30 px-6 py-4 border-b border-border">
      <h2 className="text-sm font-semibold text-muted-foreground mb-3">
        {metrics.title}
      </h2>
      <div className="grid grid-cols-4 gap-4">
        {metrics.metrics.map((metric, idx) => (
          <div
            key={idx}
            className="bg-card rounded-lg p-4 border border-border"
            data-testid={`metric-${metric.label.toLowerCase().replace(/\s+/g, '-')}`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">{metric.label}</p>
                <p className={`text-2xl font-bold ${metric.color}`}>
                  {metric.value}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
