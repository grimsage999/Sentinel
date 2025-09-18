import { storage } from "./storage";
import { type InsertThreatIntelligence } from "@shared/schema";

// Interface for threat intelligence feed sources
interface ThreatFeed {
  name: string;
  url: string;
  apiKey?: string;
  enabled: boolean;
  lastUpdate: Date | null;
  reliability: number; // 0-100 score
}

// Interface for standardized threat intelligence data
interface ThreatIntelData {
  iocValue: string;
  iocType: 'ip' | 'domain' | 'url' | 'hash';
  maliciousScore: number;
  confidence: number;
  threatActor?: string;
  campaign?: string;
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
  sources: string[];
  reputation: 'Clean' | 'Suspicious' | 'Malicious';
}

class ThreatIntelligenceManager {
  private feeds: ThreatFeed[] = [
    {
      name: "AbuseIPDB",
      url: "https://api.abuseipdb.com/api/v2/check",
      enabled: true,
      lastUpdate: null,
      reliability: 85
    },
    {
      name: "VirusTotal",
      url: "https://www.virustotal.com/vtapi/v2/",
      enabled: true,
      lastUpdate: null,
      reliability: 90
    },
    {
      name: "AlienVault OTX",
      url: "https://otx.alienvault.com/api/v1/",
      enabled: true,
      lastUpdate: null,
      reliability: 80
    },
    {
      name: "ThreatCrowd",
      url: "https://www.threatcrowd.org/searchApi/v2/",
      enabled: true,
      lastUpdate: null,
      reliability: 75
    },
    {
      name: "Shodan",
      url: "https://api.shodan.io/",
      enabled: true,
      lastUpdate: null,
      reliability: 70
    }
  ];

  private cache = new Map<string, { data: ThreatIntelData[], timestamp: Date }>();
  private readonly cacheTimeout = 5 * 60 * 1000; // 5 minutes

  // Simulate real-time threat intelligence enrichment
  async enrichIOC(iocValue: string, iocType: string): Promise<ThreatIntelData[]> {
    const cacheKey = `${iocType}:${iocValue}`;
    
    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp.getTime() < this.cacheTimeout) {
      return cached.data;
    }

    const enrichedData: ThreatIntelData[] = [];

    // Simulate enrichment from multiple sources
    for (const feed of this.feeds.filter(f => f.enabled)) {
      try {
        const data = await this.queryFeed(feed, iocValue, iocType);
        if (data) {
          enrichedData.push(data);
        }
      } catch (error) {
        console.warn(`Failed to query ${feed.name} for ${iocValue}:`, error);
      }
    }

    // Cache the results
    this.cache.set(cacheKey, { data: enrichedData, timestamp: new Date() });

    return enrichedData;
  }

  // Simulate querying individual threat feeds
  private async queryFeed(feed: ThreatFeed, iocValue: string, iocType: string): Promise<ThreatIntelData | null> {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 100));

    // Generate realistic threat intelligence data based on the feed
    const baseData: ThreatIntelData = {
      iocValue,
      iocType: iocType as any,
      maliciousScore: 0,
      confidence: feed.reliability,
      firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Last 30 days
      lastSeen: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000), // Last 7 days
      tags: [],
      sources: [feed.name],
      reputation: 'Clean'
    };

    // Customize data based on feed type
    switch (feed.name) {
      case "AbuseIPDB":
        if (iocType === 'ip') {
          baseData.maliciousScore = this.generateRealisticScore(iocValue, 'ip');
          baseData.tags = ['spam', 'malware', 'botnet'].filter(() => Math.random() > 0.7);
          baseData.reputation = baseData.maliciousScore > 70 ? 'Malicious' : 
                              baseData.maliciousScore > 30 ? 'Suspicious' : 'Clean';
        }
        break;

      case "VirusTotal":
        baseData.maliciousScore = this.generateRealisticScore(iocValue, iocType);
        baseData.tags = ['trojan', 'ransomware', 'adware', 'spyware'].filter(() => Math.random() > 0.6);
        if (baseData.maliciousScore > 60) {
          baseData.threatActor = ['APT28', 'Lazarus', 'FIN7', 'Carbanak', 'Equation Group'][Math.floor(Math.random() * 5)];
          baseData.campaign = ['WellMail', 'DarkHalo', 'SolarWinds', 'NotPetya'][Math.floor(Math.random() * 4)];
        }
        baseData.reputation = baseData.maliciousScore > 75 ? 'Malicious' : 
                            baseData.maliciousScore > 40 ? 'Suspicious' : 'Clean';
        break;

      case "AlienVault OTX":
        baseData.maliciousScore = this.generateRealisticScore(iocValue, iocType);
        baseData.tags = ['c2', 'phishing', 'exploit', 'backdoor'].filter(() => Math.random() > 0.8);
        baseData.reputation = baseData.maliciousScore > 65 ? 'Malicious' : 
                            baseData.maliciousScore > 35 ? 'Suspicious' : 'Clean';
        break;

      case "ThreatCrowd":
        if (iocType === 'domain') {
          baseData.maliciousScore = this.generateRealisticScore(iocValue, 'domain');
          baseData.tags = ['phishing', 'malware-hosting', 'c2-server'].filter(() => Math.random() > 0.7);
          baseData.reputation = baseData.maliciousScore > 70 ? 'Malicious' : 
                              baseData.maliciousScore > 30 ? 'Suspicious' : 'Clean';
        }
        break;

      case "Shodan":
        if (iocType === 'ip') {
          baseData.maliciousScore = this.generateRealisticScore(iocValue, 'ip');
          baseData.tags = ['open-port', 'vulnerable-service', 'botnet'].filter(() => Math.random() > 0.8);
          baseData.reputation = baseData.maliciousScore > 50 ? 'Suspicious' : 'Clean';
        }
        break;
    }

    // Return null for some feeds to simulate real-world scenarios where not all feeds have data
    return Math.random() > 0.3 ? baseData : null;
  }

  // Generate realistic malicious scores based on IOC characteristics
  private generateRealisticScore(iocValue: string, iocType: string): number {
    let baseScore = 0;
    
    // Create deterministic but varied scores based on IOC value
    const hash = this.simpleHash(iocValue);
    
    if (iocType === 'ip') {
      // Private IPs are generally less suspicious
      if (iocValue.startsWith('192.168.') || iocValue.startsWith('10.') || iocValue.startsWith('172.')) {
        baseScore = 5 + (hash % 20);
      } else {
        baseScore = 15 + (hash % 70);
      }
    } else if (iocType === 'domain') {
      // Suspicious patterns in domains
      if (iocValue.includes('temp') || iocValue.includes('susp') || iocValue.includes('mail')) {
        baseScore = 40 + (hash % 50);
      } else {
        baseScore = 10 + (hash % 60);
      }
    } else if (iocType === 'hash') {
      // Most hashes are either very clean or very suspicious
      baseScore = hash % 2 === 0 ? 5 + (hash % 15) : 70 + (hash % 25);
    } else {
      baseScore = 20 + (hash % 60);
    }

    return Math.min(95, Math.max(0, baseScore));
  }

  // Simple hash function for deterministic but varied results
  private simpleHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }

  // Aggregate threat intelligence from multiple sources
  async aggregateThreatIntelligence(alertId: string, iocs: string[]): Promise<InsertThreatIntelligence> {
    const allIntelData: ThreatIntelData[] = [];

    // Enrich each IOC
    for (const ioc of iocs) {
      const iocType = this.detectIOCType(ioc);
      if (iocType) {
        const intelData = await this.enrichIOC(ioc, iocType);
        allIntelData.push(...intelData);
      }
    }

    // Calculate aggregate scores
    const maliciousScores = allIntelData.map(d => d.maliciousScore).filter(s => s > 0);
    const averageScore = maliciousScores.length > 0 ? 
      maliciousScores.reduce((a, b) => a + b, 0) / maliciousScores.length : 0;

    // Determine threat actor based on highest confidence data
    const threatActorData = allIntelData
      .filter(d => d.threatActor && d.confidence > 70)
      .sort((a, b) => b.confidence - a.confidence)[0];

    // Count previous sightings across all sources
    const previousSightings = allIntelData.reduce((count, data) => {
      return count + (data.sources.length * Math.floor(Math.random() * 10));
    }, 0);

    return {
      alertId,
      maliciousScore: Math.round(averageScore),
      previousSightings: Math.min(500, previousSightings), // Cap at reasonable number
      threatActor: threatActorData?.threatActor || 'Unknown',
      iocs: allIntelData.map(d => ({
        type: d.iocType,
        value: d.iocValue,
        reputation: d.reputation,
        sources: d.sources,
        confidence: d.confidence,
        tags: d.tags
      })),
      attribution: {
        confidence: threatActorData ? 'High' : allIntelData.length > 0 ? 'Medium' : 'Low',
        campaign: threatActorData?.campaign || 'Unknown',
        sources: [...new Set(allIntelData.flatMap(d => d.sources))]
      }
    };
  }

  // Detect IOC type from value
  private detectIOCType(ioc: string): string | null {
    // IP address pattern
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ioc)) {
      return 'ip';
    }
    // Domain pattern
    if (/^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(ioc)) {
      return 'domain';
    }
    // URL pattern
    if (/^https?:\/\//.test(ioc)) {
      return 'url';
    }
    // Hash patterns
    if (/^[a-fA-F0-9]{32}$/.test(ioc) || /^[a-fA-F0-9]{40}$/.test(ioc) || /^[a-fA-F0-9]{64}$/.test(ioc)) {
      return 'hash';
    }
    return null;
  }

  // Get feed status for monitoring
  getFeedStatus(): ThreatFeed[] {
    return this.feeds.map(feed => ({
      ...feed,
      lastUpdate: feed.lastUpdate || new Date()
    }));
  }

  // Simulate live feed updates
  async startLiveFeedUpdates(): Promise<void> {
    console.log('Starting real-time threat intelligence feeds...');
    
    // Simulate periodic updates every 5 minutes
    setInterval(async () => {
      for (const feed of this.feeds.filter(f => f.enabled)) {
        feed.lastUpdate = new Date();
        console.log(`Updated feed: ${feed.name} at ${feed.lastUpdate.toISOString()}`);
      }
      
      // Clear old cache entries
      const now = Date.now();
      for (const [key, value] of this.cache.entries()) {
        if (now - value.timestamp.getTime() > this.cacheTimeout) {
          this.cache.delete(key);
        }
      }
    }, 5 * 60 * 1000); // 5 minutes

    // Mark all feeds as initially updated
    this.feeds.forEach(feed => {
      feed.lastUpdate = new Date();
    });
  }
}

export const threatIntelManager = new ThreatIntelligenceManager();