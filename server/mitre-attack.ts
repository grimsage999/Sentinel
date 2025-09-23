// MITRE ATT&CK API Integration Service
// Provides real MITRE ATT&CK framework data for threat intelligence

import fs from 'fs/promises';
import path from 'path';

interface MitreAttackData {
  spec_version: string;
  id: string;
  created: string;
  modified: string;
  objects: MitreObject[];
}

interface MitreObject {
  type: string;
  id: string;
  created: string;
  modified: string;
  name?: string;
  description?: string;
  external_references?: ExternalReference[];
  kill_chain_phases?: KillChainPhase[];
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_detection?: string;
  x_mitre_permissions_required?: string[];
  x_mitre_effective_permissions?: string[];
  x_mitre_defense_bypassed?: string[];
  x_mitre_remote_support?: boolean;
  x_mitre_system_requirements?: string[];
  x_mitre_network_requirements?: boolean;
  x_mitre_impact_type?: string[];
  x_mitre_version?: string;
  x_mitre_modified_by_ref?: string;
  x_mitre_domains?: string[];
  x_mitre_contributors?: string[];
  x_mitre_shortname?: string;
  x_mitre_deprecated?: boolean;
  revoked?: boolean;
}

interface ExternalReference {
  source_name: string;
  external_id?: string;
  url?: string;
  description?: string;
}

interface KillChainPhase {
  kill_chain_name: string;
  phase_name: string;
}

interface EnrichedMitreTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  detection: string;
  permissions_required: string[];
  defense_bypassed: string[];
  url: string;
  sub_techniques: string[];
  mitigations: string[];
  procedure_examples: ProcedureExample[];
  confidence: number;
}

interface ProcedureExample {
  group: string;
  description: string;
  reference: string;
}

interface MitreTactic {
  id: string;
  name: string;
  description: string;
  shortname: string;
  url: string;
}

class MitreAttackService {
  private apiUrl = process.env.MITRE_ATTACK_API_URL || 
    'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
  private cacheFile = path.join(process.cwd(), '.mitre-cache.json');
  private cacheTtlHours = parseInt(process.env.MITRE_ATTACK_CACHE_TTL_HOURS || '24');
  private enabled = process.env.MITRE_ATTACK_ENABLED !== 'false';
  
  private mitreData: MitreAttackData | null = null;
  private techniques: Map<string, EnrichedMitreTechnique> = new Map();
  private tactics: Map<string, MitreTactic> = new Map();

  constructor() {
    if (this.enabled) {
      this.initializeMitreData();
    }
  }

  private async initializeMitreData(): Promise<void> {
    try {
      console.log('🎯 Initializing MITRE ATT&CK framework data...');
      
      // Try to load from cache first
      const cachedData = await this.loadFromCache();
      if (cachedData) {
        this.mitreData = cachedData;
        console.log('✅ Loaded MITRE ATT&CK data from cache');
      } else {
        // Fetch fresh data from API
        await this.fetchMitreData();
        console.log('✅ Fetched fresh MITRE ATT&CK data from API');
      }

      // Process and index the data
      this.processData();
      console.log(`✅ Processed ${this.techniques.size} techniques and ${this.tactics.size} tactics`);
      
    } catch (error) {
      console.error('❌ Failed to initialize MITRE ATT&CK data:', error);
    }
  }

  private async loadFromCache(): Promise<MitreAttackData | null> {
    try {
      const stats = await fs.stat(this.cacheFile);
      const hoursSinceModified = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60);
      
      if (hoursSinceModified < this.cacheTtlHours) {
        const cached = await fs.readFile(this.cacheFile, 'utf-8');
        return JSON.parse(cached);
      }
    } catch (error) {
      // Cache file doesn't exist or is invalid
    }
    return null;
  }

  private async fetchMitreData(): Promise<void> {
    try {
      console.log(`🔄 Fetching MITRE ATT&CK data from ${this.apiUrl}`);
      const response = await fetch(this.apiUrl);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      this.mitreData = await response.json();
      
      // Cache the data
      await fs.writeFile(this.cacheFile, JSON.stringify(this.mitreData, null, 2));
      
    } catch (error) {
      console.error('❌ Failed to fetch MITRE ATT&CK data:', error);
      throw error;
    }
  }

  private processData(): void {
    if (!this.mitreData) return;

    // Process tactics first
    this.mitreData.objects
      .filter(obj => obj.type === 'x-mitre-tactic')
      .forEach(tactic => {
        const tacticId = tactic.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id;
        if (tacticId && tactic.name) {
          this.tactics.set(tacticId, {
            id: tacticId,
            name: tactic.name,
            description: tactic.description || '',
            shortname: tactic.x_mitre_shortname || tactic.name,
            url: `https://attack.mitre.org/tactics/${tacticId}`
          });
        }
      });

    // Process techniques
    this.mitreData.objects
      .filter(obj => obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated)
      .forEach(technique => {
        const techniqueId = technique.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id;
        if (techniqueId && technique.name) {
          
          const tactics = technique.kill_chain_phases?.map(phase => phase.phase_name) || [];
          
          this.techniques.set(techniqueId, {
            id: techniqueId,
            name: technique.name,
            description: technique.description || '',
            tactics,
            platforms: technique.x_mitre_platforms || [],
            data_sources: technique.x_mitre_data_sources || [],
            detection: technique.x_mitre_detection || '',
            permissions_required: technique.x_mitre_permissions_required || [],
            defense_bypassed: technique.x_mitre_defense_bypassed || [],
            url: `https://attack.mitre.org/techniques/${techniqueId}`,
            sub_techniques: [],
            mitigations: [],
            procedure_examples: [],
            confidence: 0.9
          });
        }
      });

    // Link sub-techniques to parent techniques
    this.mitreData.objects
      .filter(obj => obj.type === 'attack-pattern' && obj.external_references?.some(ref => ref.external_id?.includes('.')))
      .forEach(subTechnique => {
        const subTechId = subTechnique.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id;
        if (subTechId) {
          const parentId = subTechId.split('.')[0];
          const parentTechnique = this.techniques.get(parentId);
          if (parentTechnique) {
            parentTechnique.sub_techniques.push(subTechId);
          }
        }
      });
  }

  /**
   * Get enriched information for a MITRE ATT&CK technique
   */
  async getTechnique(techniqueId: string): Promise<EnrichedMitreTechnique | null> {
    if (!this.enabled || !this.techniques.has(techniqueId)) {
      return null;
    }

    return this.techniques.get(techniqueId) || null;
  }

  /**
   * Get enriched information for multiple MITRE ATT&CK techniques
   */
  async getTechniques(techniqueIds: string[]): Promise<EnrichedMitreTechnique[]> {
    if (!this.enabled) return [];

    const results: EnrichedMitreTechnique[] = [];
    
    for (const id of techniqueIds) {
      const technique = this.techniques.get(id);
      if (technique) {
        results.push(technique);
      }
    }

    return results;
  }

  /**
   * Get MITRE ATT&CK tactic information
   */
  async getTactic(tacticId: string): Promise<MitreTactic | null> {
    if (!this.enabled || !this.tactics.has(tacticId)) {
      return null;
    }

    return this.tactics.get(tacticId) || null;
  }

  /**
   * Get MITRE ATT&CK tactics information
   */
  async getTactics(tacticIds: string[]): Promise<MitreTactic[]> {
    if (!this.enabled) return [];

    const results: MitreTactic[] = [];
    
    for (const id of tacticIds) {
      const tactic = this.tactics.get(id);
      if (tactic) {
        results.push(tactic);
      }
    }

    return results;
  }

  /**
   * Search techniques by name or description
   */
  async searchTechniques(query: string, limit: number = 10): Promise<EnrichedMitreTechnique[]> {
    if (!this.enabled) return [];

    const results: EnrichedMitreTechnique[] = [];
    const lowerQuery = query.toLowerCase();

    for (const technique of this.techniques.values()) {
      if (
        technique.name.toLowerCase().includes(lowerQuery) ||
        technique.description.toLowerCase().includes(lowerQuery)
      ) {
        results.push(technique);
        if (results.length >= limit) break;
      }
    }

    return results;
  }

  /**
   * Get techniques by tactic
   */
  async getTechniquesByTactic(tacticName: string): Promise<EnrichedMitreTechnique[]> {
    if (!this.enabled) return [];

    const results: EnrichedMitreTechnique[] = [];
    
    for (const technique of this.techniques.values()) {
      if (technique.tactics.includes(tacticName)) {
        results.push(technique);
      }
    }

    return results;
  }

  /**
   * Get all available tactics
   */
  async getAllTactics(): Promise<MitreTactic[]> {
    if (!this.enabled) return [];
    return Array.from(this.tactics.values());
  }

  /**
   * Get service status
   */
  getStatus(): { enabled: boolean; techniques: number; tactics: number; lastUpdate?: string } {
    return {
      enabled: this.enabled,
      techniques: this.techniques.size,
      tactics: this.tactics.size,
      lastUpdate: this.mitreData?.modified
    };
  }

  /**
   * Force refresh of MITRE data
   */
  async refresh(): Promise<void> {
    try {
      // Delete cache file to force refresh
      await fs.unlink(this.cacheFile).catch(() => {});
      await this.fetchMitreData();
      this.processData();
      console.log('✅ MITRE ATT&CK data refreshed successfully');
    } catch (error) {
      console.error('❌ Failed to refresh MITRE ATT&CK data:', error);
      throw error;
    }
  }
}

// Create and export singleton instance
export const mitreAttackService = new MitreAttackService();
export type { EnrichedMitreTechnique, MitreTactic };
