import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import Header from "@/components/header";
import MetricsBar from "@/components/metrics-bar";
import AlertsList from "@/components/alerts-list";
import AlertDetails from "@/components/alert-details";
import RightPanel from "@/components/right-panel";
import IOCEnrichmentModal from "@/components/ioc-enrichment-modal";
import { api } from "@/lib/api";
import type { Alert } from "@shared/schema";
import type { UserRole } from "@/types";

export default function Dashboard() {
  const [currentRole, setCurrentRole] = useState<UserRole>("analyst");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [showIOCModal, setShowIOCModal] = useState(false);

  const {
    data: alerts = [],
    isLoading: alertsLoading,
    refetch: refetchAlerts
  } = useQuery({
    queryKey: ["/api/alerts"],
    queryFn: () => api.getAlerts()
  });

  const {
    data: auditLog = [],
    refetch: refetchAuditLog
  } = useQuery({
    queryKey: ["/api/audit-log"],
    queryFn: () => api.getAuditLog()
  });

  // Auto-refresh alerts every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      refetchAlerts();
    }, 10000);
    return () => clearInterval(interval);
  }, [refetchAlerts]);

  const handleRoleSwitch = (role: UserRole) => {
    setCurrentRole(role);
    api.createAuditEntry("USER", `Switched to ${role} view`);
    refetchAuditLog();
  };

  const handleAlertSelect = (alert: Alert) => {
    setSelectedAlert(alert);
    api.createAuditEntry("USER", `Opened alert ${alert.id} for investigation`, alert.id);
    refetchAuditLog();
  };

  const handleRefresh = () => {
    refetchAlerts();
    refetchAuditLog();
    api.createAuditEntry("USER", "Manually refreshed dashboard");
  };

  const handleIOCEnrichment = () => {
    setShowIOCModal(true);
    if (selectedAlert) {
      api.createAuditEntry("USER", `Opened IOC enrichment for alert ${selectedAlert.id}`, selectedAlert.id);
      refetchAuditLog();
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header 
        currentRole={currentRole}
        onRoleSwitch={handleRoleSwitch}
        onRefresh={handleRefresh}
      />
      
      <MetricsBar currentRole={currentRole} />
      
      <div className="flex h-[calc(100vh-200px)]">
        <AlertsList
          alerts={alerts}
          selectedAlert={selectedAlert}
          onAlertSelect={handleAlertSelect}
          isLoading={alertsLoading}
        />
        
        <AlertDetails
          alert={selectedAlert}
          onIOCEnrichment={handleIOCEnrichment}
        />
        
        <RightPanel auditLog={auditLog} />
      </div>

      <IOCEnrichmentModal
        isOpen={showIOCModal}
        onClose={() => setShowIOCModal(false)}
        alertId={selectedAlert?.id}
      />
    </div>
  );
}
