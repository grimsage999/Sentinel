"""
Threat Intelligence Services Module

This module provides automated threat intelligence gathering and processing
capabilities for the Cognito AI Agent Framework.

Components:
- ThreatIntelligenceHarvester: Collects threat data from RSS feeds and web sources
- ThreatIntelligenceProcessor: Processes and extracts IOCs from raw threat data
- ThreatIntelService: Query interface for processed threat intelligence
"""

from .harvester import ThreatIntelligenceHarvester
from .processor import ThreatIntelligenceProcessor
from .service import ThreatIntelService

__all__ = [
    'ThreatIntelligenceHarvester',
    'ThreatIntelligenceProcessor',
    'ThreatIntelService',
]