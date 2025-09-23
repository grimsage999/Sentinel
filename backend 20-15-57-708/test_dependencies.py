#!/usr/bin/env python3
"""
Test Dependencies
Tests if the dependency injection is working
"""

import sys
import os
sys.path.append('/Users/kelvin/Desktop/kelveloper/IBM_FISHING/backend')

from dotenv import load_dotenv
load_dotenv()

from app.api.dependencies import get_analysis_services

def test_dependencies():
    """Test if dependencies can be loaded"""
    print("🔧 Testing Dependencies")
    print("=" * 30)
    
    try:
        print("Loading analysis services...")
        services = get_analysis_services()
        print(f"✅ Services loaded: {list(services.keys())}")
        
        # Test each service
        for name, service in services.items():
            print(f"   {name}: {type(service).__name__}")
        
        return True
    except Exception as e:
        print(f"❌ Dependency loading failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_dependencies()
    
    print("\n" + "=" * 30)
    if success:
        print("✅ Dependencies working!")
    else:
        print("❌ Dependencies failed!")