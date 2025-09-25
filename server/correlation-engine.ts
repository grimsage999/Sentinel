import { and, desc, eq, gte, inArray, ne, sql, isNotNull } from "drizzle-orm";
import { db } from "./db";
import { alerts, correlations, iocs, threatIntelligence } from "@shared/schema";
import type { Alert, Correlation, InsertCorrelation } from "@shared/schema";

export interface CorrelationResult {
  correlation: Correlation;
  primaryAlert: Alert;
  relatedAlert: Alert;
  correlationStrength: number;
}

export interface CorrelationAnalysis {
  alertId: string;
  correlations: CorrelationResult[];
  totalScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  patterns: string[];
}

export class CorrelationEngine {
  private static readonly CORRELATION_TYPES = {
    IOC_OVERLAP: "ioc_overlap",
    TIME_PROXIMITY: "time_proximity", 
    SOURCE_SIMILARITY: "source_similarity",
    THREAT_ACTOR: "threat_actor",
    CAMPAIGN: "campaign",
    SEVERITY_ESCALATION: "severity_escalation",
    ASSET_TARGETING: "asset_targeting"
  } as const;

  private static readonly TIME_WINDOWS = {
    IMMEDIATE: 5 * 60 * 1000, // 5 minutes
    SHORT: 30 * 60 * 1000,    // 30 minutes  
    MEDIUM: 6 * 60 * 60 * 1000, // 6 hours
    LONG: 24 * 60 * 60 * 1000   // 24 hours
  } as const;

  private static readonly CONFIDENCE_THRESHOLDS = {
    HIGH: 80,
    MEDIUM: 60,
    LOW: 40
  } as const;

  /**
   * Analyze correlations for a specific alert
   */
  async analyzeAlert(alertId: string): Promise<CorrelationAnalysis> {
    const alert = await db().select().from(alerts).where(eq(alerts.id, alertId)).limit(1);
    if (!alert.length) {
      throw new Error(`Alert ${alertId} not found`);
    }

    const currentAlert = alert[0];
    const correlationResults: CorrelationResult[] = [];
    
    // Run all correlation analyses in parallel
    const [
      iocCorrelations,
      timeCorrelations, 
      sourceCorrelations,
      threatActorCorrelations,
      campaignCorrelations,
      escalationCorrelations,
      assetCorrelations
    ] = await Promise.all([
      this.findIOCOverlapCorrelations(currentAlert),
      this.findTimeProximityCorrelations(currentAlert),
      this.findSourceSimilarityCorrelations(currentAlert),
      this.findThreatActorCorrelations(currentAlert),
      this.findCampaignCorrelations(currentAlert),
      this.findSeverityEscalationCorrelations(currentAlert),
      this.findAssetTargetingCorrelations(currentAlert)
    ]);

    correlationResults.push(
      ...iocCorrelations,
      ...timeCorrelations,
      ...sourceCorrelations, 
      ...threatActorCorrelations,
      ...campaignCorrelations,
      ...escalationCorrelations,
      ...assetCorrelations
    );

    // Remove duplicates and sort by correlation strength
    const uniqueCorrelations = this.deduplicateCorrelations(correlationResults);
    uniqueCorrelations.sort((a, b) => b.correlationStrength - a.correlationStrength);

    // Calculate overall risk assessment
    const totalScore = this.calculateTotalScore(uniqueCorrelations);
    const riskLevel = this.determineRiskLevel(totalScore, uniqueCorrelations.length);
    const patterns = this.identifyPatterns(uniqueCorrelations);

    // Store correlations in database
    await this.storeCorrelations(alertId, uniqueCorrelations);

    return {
      alertId,
      correlations: uniqueCorrelations,
      totalScore,
      riskLevel,
      patterns
    };
  }

  /**
   * Find correlations based on shared IOCs
   */
  private async findIOCOverlapCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    // Get IOCs for this alert
    const alertIOCs = await db().select().from(iocs).where(eq(iocs.alertId, alert.id));
    if (!alertIOCs.length) return [];

    const iocValues = alertIOCs.map(ioc => ioc.value);

    // Find other alerts with shared IOCs
    const sharedIOCAlerts = await db()
      .select({
        alertId: iocs.alertId,
        alert: alerts,
        iocValue: iocs.value,
        iocType: iocs.type,
        reputation: iocs.reputation
      })
      .from(iocs)
      .innerJoin(alerts, eq(iocs.alertId, alerts.id))
      .where(
        and(
          inArray(iocs.value, iocValues),
          ne(iocs.alertId, alert.id),
          isNotNull(iocs.alertId)
        )
      );

    // Group by alert and calculate overlap scores
    const alertGroups = new Map<string, any[]>();
    sharedIOCAlerts.forEach(result => {
      if (!alertGroups.has(result.alertId!)) {
        alertGroups.set(result.alertId!, []);
      }
      alertGroups.get(result.alertId!)!.push(result);
    });

    const correlations: CorrelationResult[] = [];
    for (const [relatedAlertId, sharedIOCs] of Array.from(alertGroups.entries())) {
      const overlapCount = sharedIOCs.length;
      const totalIOCs = alertIOCs.length;
      const overlapPercentage = (overlapCount / totalIOCs) * 100;
      
      // Higher confidence for more IOC overlap and malicious IOCs
      const maliciousIOCs = sharedIOCs.filter(ioc => ioc.reputation === "Malicious").length;
      const confidenceBase = Math.min(90, overlapPercentage * 0.8 + maliciousIOCs * 15);
      const confidence = Math.max(50, confidenceBase);

      if (confidence >= CorrelationEngine.CONFIDENCE_THRESHOLDS.LOW) {
        correlations.push({
          correlation: {
            id: "",
            primaryAlertId: alert.id,
            relatedAlertId,
            correlationType: CorrelationEngine.CORRELATION_TYPES.IOC_OVERLAP,
            confidence: Math.round(confidence),
            correlationData: {
              sharedIOCs: sharedIOCs.map((ioc: any) => ({
                value: ioc.iocValue,
                type: ioc.iocType,
                reputation: ioc.reputation
              })),
              overlapCount,
              overlapPercentage: Math.round(overlapPercentage)
            },
            createdAt: new Date()
          },
          primaryAlert: alert,
          relatedAlert: sharedIOCs[0].alert,
          correlationStrength: confidence
        });
      }
    }

    return correlations;
  }

  /**
   * Find correlations based on time proximity
   */
  private async findTimeProximityCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    const alertTime = alert.timestamp;
    const correlations: CorrelationResult[] = [];

    // Check different time windows
    for (const [windowName, windowMs] of Object.entries(CorrelationEngine.TIME_WINDOWS)) {
      const startTime = new Date(alertTime.getTime() - windowMs);
      const endTime = new Date(alertTime.getTime() + windowMs);

      const proximateAlerts = await db()
        .select()
        .from(alerts)
        .where(
          and(
            ne(alerts.id, alert.id),
            gte(alerts.timestamp, startTime),
            sql`${alerts.timestamp} <= ${endTime}`
          )
        );

      for (const relatedAlert of proximateAlerts) {
        const timeDiff = Math.abs(alertTime.getTime() - relatedAlert.timestamp.getTime());
        const timeScore = Math.max(0, 100 - (timeDiff / windowMs) * 100);
        
        // Boost confidence for same source or similar types
        let confidence = timeScore * 0.6;
        if (alert.source === relatedAlert.source) confidence += 15;
        if (alert.type === relatedAlert.type) confidence += 10;
        if (alert.severity === relatedAlert.severity) confidence += 5;

        confidence = Math.min(95, confidence);

        if (confidence >= CorrelationEngine.CONFIDENCE_THRESHOLDS.LOW) {
          correlations.push({
            correlation: {
              id: "",
              primaryAlertId: alert.id,
              relatedAlertId: relatedAlert.id,
              correlationType: CorrelationEngine.CORRELATION_TYPES.TIME_PROXIMITY,
              confidence: Math.round(confidence),
              correlationData: {
                timeWindow: windowName,
                timeDifferenceMs: timeDiff,
                timeDifferenceMinutes: Math.round(timeDiff / (1000 * 60)),
                sameSource: alert.source === relatedAlert.source,
                sameType: alert.type === relatedAlert.type
              },
              createdAt: new Date()
            },
            primaryAlert: alert,
            relatedAlert,
            correlationStrength: confidence
          });
        }
      }
    }

    return correlations;
  }

  /**
   * Find correlations based on source similarity
   */
  private async findSourceSimilarityCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    const sameSourceAlerts = await db()
      .select()
      .from(alerts)
      .where(
        and(
          eq(alerts.source, alert.source),
          ne(alerts.id, alert.id)
        )
      )
      .orderBy(desc(alerts.timestamp))
      .limit(10);

    const correlations: CorrelationResult[] = [];
    for (const relatedAlert of sameSourceAlerts) {
      let confidence = 50; // Base confidence for same source
      
      // Boost for same alert type
      if (alert.type === relatedAlert.type) confidence += 20;
      
      // Boost for similar severity
      if (alert.severity === relatedAlert.severity) confidence += 15;
      
      // Boost for recent alerts
      const timeDiff = Math.abs(alert.timestamp.getTime() - relatedAlert.timestamp.getTime());
      const hoursAgo = timeDiff / (1000 * 60 * 60);
      if (hoursAgo < 24) confidence += 10;

      if (confidence >= CorrelationEngine.CONFIDENCE_THRESHOLDS.LOW) {
        correlations.push({
          correlation: {
            id: "",
            primaryAlertId: alert.id,
            relatedAlertId: relatedAlert.id,
            correlationType: CorrelationEngine.CORRELATION_TYPES.SOURCE_SIMILARITY,
            confidence: Math.round(confidence),
            correlationData: {
              source: alert.source,
              sameType: alert.type === relatedAlert.type,
              sameSeverity: alert.severity === relatedAlert.severity,
              hoursApart: Math.round(hoursAgo)
            },
            createdAt: new Date()
          },
          primaryAlert: alert,
          relatedAlert,
          correlationStrength: confidence
        });
      }
    }

    return correlations;
  }

  /**
   * Find correlations based on threat actor attribution
   */
  private async findThreatActorCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    const threatIntel = await db()
      .select()
      .from(threatIntelligence)
      .where(eq(threatIntelligence.alertId, alert.id))
      .limit(1);

    if (!threatIntel.length || !threatIntel[0].threatActor) return [];

    const threatActor = threatIntel[0].threatActor;
    
    const relatedThreatIntel = await db()
      .select({
        threatIntel: threatIntelligence,
        alert: alerts
      })
      .from(threatIntelligence)
      .innerJoin(alerts, eq(threatIntelligence.alertId, alerts.id))
      .where(
        and(
          eq(threatIntelligence.threatActor, threatActor),
          ne(alerts.id, alert.id)
        )
      );

    const correlations: CorrelationResult[] = [];
    for (const result of relatedThreatIntel) {
      const confidence = 85; // High confidence for same threat actor

      correlations.push({
        correlation: {
          id: "",
          primaryAlertId: alert.id,
          relatedAlertId: result.alert.id,
          correlationType: CorrelationEngine.CORRELATION_TYPES.THREAT_ACTOR,
          confidence,
          correlationData: {
            threatActor,
            attribution: result.threatIntel.attribution
          },
          createdAt: new Date()
        },
        primaryAlert: alert,
        relatedAlert: result.alert,
        correlationStrength: confidence
      });
    }

    return correlations;
  }

  /**
   * Find correlations based on campaign attribution
   */
  private async findCampaignCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    const threatIntel = await db()
      .select()
      .from(threatIntelligence)  
      .where(eq(threatIntelligence.alertId, alert.id))
      .limit(1);

    if (!threatIntel.length || !threatIntel[0].attribution) return [];

    const attribution = threatIntel[0].attribution as any;
    const campaign = attribution?.campaign;
    
    if (!campaign) return [];

    const relatedCampaignIntel = await db()
      .select({
        threatIntel: threatIntelligence,
        alert: alerts
      })
      .from(threatIntelligence)
      .innerJoin(alerts, eq(threatIntelligence.alertId, alerts.id))
      .where(
        and(
          sql`${threatIntelligence.attribution}->>'campaign' = ${campaign}`,
          ne(alerts.id, alert.id)
        )
      );

    const correlations: CorrelationResult[] = [];
    for (const result of relatedCampaignIntel) {
      const confidence = 80; // High confidence for same campaign

      correlations.push({
        correlation: {
          id: "",
          primaryAlertId: alert.id,
          relatedAlertId: result.alert.id,
          correlationType: CorrelationEngine.CORRELATION_TYPES.CAMPAIGN,
          confidence,
          correlationData: {
            campaign,
            attribution: result.threatIntel.attribution
          },
          createdAt: new Date()
        },
        primaryAlert: alert,
        relatedAlert: result.alert,
        correlationStrength: confidence
      });
    }

    return correlations;
  }

  /**
   * Find correlations based on severity escalation patterns
   */
  private async findSeverityEscalationCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    const severityOrder = { "Low": 1, "Medium": 2, "High": 3, "Critical": 4 };
    const currentSeverityLevel = severityOrder[alert.severity as keyof typeof severityOrder] || 0;

    // Look for alerts that escalated in severity within the last 24 hours
    const last24Hours = new Date(alert.timestamp.getTime() - CorrelationEngine.TIME_WINDOWS.LONG);
    
    const escalationAlerts = await db
      .select()
      .from(alerts)
      .where(
        and(
          ne(alerts.id, alert.id),
          gte(alerts.timestamp, last24Hours)
        )
      );

    const correlations: CorrelationResult[] = [];
    for (const relatedAlert of escalationAlerts) {
      const relatedSeverityLevel = severityOrder[relatedAlert.severity as keyof typeof severityOrder] || 0;
      
      // Check for escalation pattern
      if (relatedSeverityLevel < currentSeverityLevel) {
        const escalationLevels = currentSeverityLevel - relatedSeverityLevel;
        const confidence = Math.min(75, 40 + escalationLevels * 15);

        correlations.push({
          correlation: {
            id: "",
            primaryAlertId: alert.id,
            relatedAlertId: relatedAlert.id,
            correlationType: CorrelationEngine.CORRELATION_TYPES.SEVERITY_ESCALATION,
            confidence,
            correlationData: {
              fromSeverity: relatedAlert.severity,
              toSeverity: alert.severity,
              escalationLevels
            },
            createdAt: new Date()
          },
          primaryAlert: alert,
          relatedAlert,
          correlationStrength: confidence
        });
      }
    }

    return correlations;
  }

  /**
   * Find correlations based on asset targeting patterns
   */
  private async findAssetTargetingCorrelations(alert: Alert): Promise<CorrelationResult[]> {
    if (!alert.affectedAssets) return [];

    const assetTargetingAlerts = await db
      .select()
      .from(alerts)
      .where(
        and(
          ne(alerts.id, alert.id),
          isNotNull(alerts.affectedAssets)
        )
      );

    const correlations: CorrelationResult[] = [];
    for (const relatedAlert of assetTargetingAlerts) {
      if (!relatedAlert.affectedAssets) continue;

      // Calculate asset overlap (simplified - in reality would need more sophisticated asset tracking)
      const confidence = alert.affectedAssets === relatedAlert.affectedAssets ? 70 : 45;

      if (confidence >= CorrelationEngine.CONFIDENCE_THRESHOLDS.LOW) {
        correlations.push({
          correlation: {
            id: "",
            primaryAlertId: alert.id,
            relatedAlertId: relatedAlert.id,
            correlationType: CorrelationEngine.CORRELATION_TYPES.ASSET_TARGETING,
            confidence,
            correlationData: {
              affectedAssets: alert.affectedAssets,
              relatedAffectedAssets: relatedAlert.affectedAssets,
              exactMatch: alert.affectedAssets === relatedAlert.affectedAssets
            },
            createdAt: new Date()
          },
          primaryAlert: alert,
          relatedAlert,
          correlationStrength: confidence
        });
      }
    }

    return correlations;
  }

  /**
   * Remove duplicate correlations and merge similar ones
   */
  private deduplicateCorrelations(correlations: CorrelationResult[]): CorrelationResult[] {
    const seen = new Map<string, CorrelationResult>();
    
    for (const correlation of correlations) {
      const key = `${correlation.correlation.primaryAlertId}-${correlation.correlation.relatedAlertId}`;
      const existing = seen.get(key);
      
      if (!existing || correlation.correlationStrength > existing.correlationStrength) {
        seen.set(key, correlation);
      }
    }
    
    return Array.from(seen.values());
  }

  /**
   * Calculate total correlation score
   */
  private calculateTotalScore(correlations: CorrelationResult[]): number {
    if (!correlations.length) return 0;
    
    const totalStrength = correlations.reduce((sum, corr) => sum + corr.correlationStrength, 0);
    return Math.round(totalStrength / correlations.length);
  }

  /**
   * Determine overall risk level
   */
  private determineRiskLevel(totalScore: number, correlationCount: number): "Low" | "Medium" | "High" | "Critical" {
    if (totalScore >= 80 && correlationCount >= 3) return "Critical";
    if (totalScore >= 70 || correlationCount >= 5) return "High";
    if (totalScore >= 50 || correlationCount >= 2) return "Medium";
    return "Low";
  }

  /**
   * Identify patterns from correlations
   */
  private identifyPatterns(correlations: CorrelationResult[]): string[] {
    const patterns: string[] = [];
    const typeCount = new Map<string, number>();
    
    correlations.forEach(corr => {
      const type = corr.correlation.correlationType;
      typeCount.set(type, (typeCount.get(type) || 0) + 1);
    });

    if (typeCount.get(CorrelationEngine.CORRELATION_TYPES.IOC_OVERLAP)! >= 2) {
      patterns.push("Multiple IOC overlap incidents detected");
    }
    
    if (typeCount.get(CorrelationEngine.CORRELATION_TYPES.TIME_PROXIMITY)! >= 3) {
      patterns.push("Coordinated attack pattern identified");
    }
    
    if (typeCount.get(CorrelationEngine.CORRELATION_TYPES.THREAT_ACTOR)) {
      patterns.push("Threat actor attribution available");
    }
    
    if (typeCount.get(CorrelationEngine.CORRELATION_TYPES.CAMPAIGN)) {
      patterns.push("Campaign attribution identified");
    }
    
    if (typeCount.get(CorrelationEngine.CORRELATION_TYPES.SEVERITY_ESCALATION)) {
      patterns.push("Severity escalation pattern detected");
    }

    return patterns;
  }

  /**
   * Store correlations in database
   */
  private async storeCorrelations(alertId: string, correlationResults: CorrelationResult[]): Promise<void> {
    const insertData: InsertCorrelation[] = correlationResults.map(result => ({
      primaryAlertId: result.correlation.primaryAlertId,
      relatedAlertId: result.correlation.relatedAlertId,
      correlationType: result.correlation.correlationType,
      confidence: result.correlation.confidence,
      correlationData: result.correlation.correlationData as any
    }));

    if (insertData.length > 0) {
      await db().insert(correlations).values(insertData).onConflictDoNothing();
    }
  }

  /**
   * Get existing correlations for an alert
   */
  async getCorrelations(alertId: string): Promise<CorrelationResult[]> {
    const storedCorrelations = await db
      .select({
        correlation: correlations,
        primaryAlert: alerts,
        relatedAlert: alerts
      })
      .from(correlations)
      .leftJoin(alerts, eq(correlations.primaryAlertId, alerts.id))
      .where(eq(correlations.primaryAlertId, alertId))
      .orderBy(desc(correlations.confidence));

    return storedCorrelations.map(result => ({
      correlation: result.correlation,
      primaryAlert: result.primaryAlert!,
      relatedAlert: result.relatedAlert!,
      correlationStrength: result.correlation.confidence
    }));
  }

  /**
   * Run correlation analysis on all unprocessed alerts
   */
  async runBatchCorrelationAnalysis(): Promise<void> {
    const recentAlerts = await db
      .select()
      .from(alerts)
      .orderBy(desc(alerts.timestamp))
      .limit(50);

    for (const alert of recentAlerts) {
      try {
        await this.analyzeAlert(alert.id);
      } catch (error) {
        console.error(`Failed to analyze correlations for alert ${alert.id}:`, error);
      }
    }
  }
}

export const correlationEngine = new CorrelationEngine();