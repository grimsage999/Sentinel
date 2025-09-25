#!/usr/bin/env python3
"""
Quick test script for Threat Intelligence services
Tests basic functionality of harvester, processor, and service components
"""

import asyncio
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from services.threat_intelligence import (
    ThreatIntelligenceHarvester,
    ThreatIntelligenceProcessor,
    ThreatIntelService
)

async def test_threat_intelligence():
    """Test the threat intelligence pipeline"""
    print("🔍 Testing Threat Intelligence Services...")
    
    # Initialize services with test database
    test_db_path = "test_threat_intel.db"
    
    try:
        # Test 1: Initialize Harvester
        print("\n1️⃣ Initializing ThreatIntelligenceHarvester...")
        harvester = ThreatIntelligenceHarvester(db_path=test_db_path)
        print("✅ Harvester initialized successfully")
        
        # Test 2: Initialize Processor  
        print("\n2️⃣ Initializing ThreatIntelligenceProcessor...")
        processor = ThreatIntelligenceProcessor(db_path=test_db_path)
        print("✅ Processor initialized successfully")
        
        # Test 3: Initialize Service
        print("\n3️⃣ Initializing ThreatIntelService...")
        service = ThreatIntelService(db_path=test_db_path)
        print("✅ Service initialized successfully")
        
        # Test 4: Harvest from one source (limit to save credits)
        print("\n4️⃣ Testing threat intelligence harvesting...")
        # Use only one lightweight source for testing
        test_sources = [{
            "name": "Test SANS ISC Feed",
            "url": "https://isc.sans.edu/rssfeed.xml",
            "type": "rss",
            "credibility_score": 85
        }]
        
        harvester.sources = test_sources  # Override with test sources
        harvest_results = await harvester.harvest_all_sources()
        
        print(f"✅ Harvest completed:")
        print(f"   - Sources processed: {harvest_results['sources_processed']}")
        print(f"   - Entries collected: {harvest_results['entries_collected']}") 
        print(f"   - New entries: {harvest_results['entries_new']}")
        if harvest_results['errors']:
            print(f"   - Errors: {harvest_results['errors']}")
        
        # Test 5: Process harvested data
        if harvest_results['entries_new'] > 0:
            print("\n5️⃣ Testing IOC processing...")
            process_results = await processor.process_all_unprocessed()
            
            print(f"✅ Processing completed:")
            print(f"   - Entries processed: {process_results['entries_processed']}")
            print(f"   - IOCs extracted: {process_results['iocs_extracted']}")
        else:
            print("\n5️⃣ No new entries to process (likely cached)")
            
        # Test 6: Query service capabilities
        print("\n6️⃣ Testing ThreatIntelService query capabilities...")
        
        # Get recent IOCs
        recent_iocs = await service.get_recent_iocs(hours=24, min_confidence=70)
        print(f"✅ Found {len(recent_iocs)} high-confidence IOCs in the last 24 hours")
        
        if recent_iocs:
            print("   Sample IOCs:")
            for ioc in recent_iocs[:3]:  # Show first 3
                print(f"   - {ioc['ioc_type']}: {ioc['ioc_value']} (confidence: {ioc['confidence_score']})")
                
        # Test threat summary
        summary = await service.get_threat_summary(hours=24)
        print(f"\n✅ Threat Intelligence Summary:")
        print(f"   - Total IOCs: {summary['total_iocs']}")
        print(f"   - IOC types: {len(summary['ioc_breakdown'])}")
        print(f"   - Sources: {len(summary['source_breakdown'])}")
        
        # Test 7: Test IOC lookup functionality
        if recent_iocs:
            print("\n7️⃣ Testing IOC lookup functionality...")
            test_ioc = recent_iocs[0]['ioc_value']
            threat_intel = await service.check_ioc_threat_intelligence(test_ioc)
            
            if threat_intel:
                print(f"✅ Found threat intelligence for IOC: {test_ioc}")
                print(f"   - Threat level: {threat_intel['threat_level']}")
                print(f"   - Confidence: {threat_intel['confidence_score']}")
                print(f"   - Source: {threat_intel['source']}")
            else:
                print(f"ℹ️ No specific threat intelligence found for: {test_ioc}")
        
        # Cleanup
        await harvester.close()
        print("\n🎉 All threat intelligence tests passed!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup test database
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print(f"🧹 Cleaned up test database: {test_db_path}")

if __name__ == "__main__":
    success = asyncio.run(test_threat_intelligence())
    sys.exit(0 if success else 1)