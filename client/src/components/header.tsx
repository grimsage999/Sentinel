import { Shield, RefreshCw, Bell, User, Terminal, Users, BarChart3, Mail, Home } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import type { UserRole } from "@/types";

interface HeaderProps {
  currentRole: UserRole;
  onRoleSwitch: (role: UserRole) => void;
  onRefresh: () => void;
}

export default function Header({ currentRole, onRoleSwitch, onRefresh }: HeaderProps) {
  const [location] = useLocation();
  
  return (
    <header className="bg-card border-b border-border px-6 py-4 relative">
      <div className="cyber-grid absolute inset-0 opacity-30"></div>
      <div className="relative flex justify-between items-center">
        <div className="flex items-center space-x-4">
          <Shield className="w-8 h-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold gradient-text">
              Cyber-Sentinel Workbench
            </h1>
            <p className="text-sm text-muted-foreground">
              Advanced Threat Intelligence Platform
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Navigation */}
          <div className="flex bg-secondary rounded-lg p-1">
            <Link href="/dashboard">
              <Button
                variant={location === "/" || location === "/dashboard" ? "default" : "ghost"}
                size="sm"
                className="px-4 py-2"
              >
                <Home className="w-4 h-4 mr-2" />
                Dashboard
              </Button>
            </Link>
            <Link href="/email-analysis">
              <Button
                variant={location === "/email-analysis" ? "default" : "ghost"}
                size="sm"
                className="px-4 py-2"
              >
                <Mail className="w-4 h-4 mr-2" />
                Email Analysis
              </Button>
            </Link>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex bg-secondary rounded-lg p-1">
            <Button
              variant={currentRole === "analyst" ? "default" : "ghost"}
              size="sm"
              onClick={() => onRoleSwitch("analyst")}
              className="px-4 py-2"
              data-testid="button-role-analyst"
            >
              <Terminal className="w-4 h-4 mr-2" />
              Analyst
            </Button>
            <Button
              variant={currentRole === "manager" ? "default" : "ghost"}
              size="sm"
              onClick={() => onRoleSwitch("manager")}
              className="px-4 py-2"
              data-testid="button-role-manager"
            >
              <Users className="w-4 h-4 mr-2" />
              Manager
            </Button>
            <Button
              variant={currentRole === "executive" ? "default" : "ghost"}
              size="sm"
              onClick={() => onRoleSwitch("executive")}
              className="px-4 py-2"
              data-testid="button-role-executive"
            >
              <BarChart3 className="w-4 h-4 mr-2" />
              Executive
            </Button>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-2 bg-secondary px-3 py-2 rounded-lg">
              <div className="w-2 h-2 bg-green-500 rounded-full status-pulse"></div>
              <span className="text-sm">Live</span>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={onRefresh}
              className="p-2"
              data-testid="button-refresh"
            >
              <RefreshCw className="w-5 h-5" />
            </Button>
            <Button variant="ghost" size="sm" className="p-2" data-testid="button-notifications">
              <Bell className="w-5 h-5" />
            </Button>
            <div className="flex items-center space-x-2 bg-secondary px-3 py-2 rounded-lg">
              <User className="w-4 h-4" />
              <span className="text-sm">Alex Chen</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
