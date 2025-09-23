"""
VirusTotal API service for automatic URL submission and analysis.
"""

import asyncio
import hashlib
import httpx
from typing import Optional, Dict, Any
from ..core.config import settings
from ..utils.logging import get_secure_logger

logger = get_secure_logger(__name__)


class VirusTotalService:
    """Service for interacting with VirusTotal API."""
    
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
    
    def _get_url_id(self, url: str) -> str:
        """Generate VirusTotal URL ID from URL using base64 encoding."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    def _get_vt_gui_url(self, url_id: str) -> str:
        """Generate VirusTotal GUI URL for analysis results."""
        return f"https://www.virustotal.com/gui/url/{url_id}"
    
    async def check_url_analysis(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check if URL analysis exists in VirusTotal.
        
        Args:
            url: URL to check
            
        Returns:
            Analysis data if exists, None if not found
        """
        if not self.api_key or self.api_key == "your_virustotal_api_key_here":
            logger.warning("VirusTotal API key not configured")
            return None
        
        url_id = self._get_url_id(url)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers=self.headers,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    logger.info(f"Found existing VirusTotal analysis for URL: {url}")
                    return response.json()
                elif response.status_code == 404:
                    logger.info(f"No existing VirusTotal analysis for URL: {url}")
                    return None
                else:
                    logger.warning(f"VirusTotal API error: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error checking VirusTotal analysis: {str(e)}")
            return None
    
    async def rescan_url(self, url: str) -> Optional[str]:
        """
        Request a URL rescan (re-analyze) in VirusTotal.
        
        Args:
            url: URL to rescan
            
        Returns:
            Analysis ID if successful, None if failed
        """
        if not self.api_key or self.api_key == "your_virustotal_api_key_here":
            logger.warning("VirusTotal API key not configured")
            return None
        
        url_id = self._get_url_id(url)
        
        try:
            async with httpx.AsyncClient() as client:
                # Request URL rescan
                headers = {"x-apikey": self.api_key}
                response = await client.post(
                    f"{self.base_url}/urls/{url_id}/analyse",
                    headers=headers,
                    timeout=15.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    analysis_id = result.get("data", {}).get("id")
                    logger.info(f"Successfully requested VirusTotal rescan for URL: {url}")
                    return analysis_id
                else:
                    logger.warning(f"VirusTotal rescan failed: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error requesting VirusTotal rescan: {str(e)}")
            return None

    async def submit_url_for_analysis(self, url: str) -> Optional[str]:
        """
        Submit URL to VirusTotal for analysis.
        
        Args:
            url: URL to submit
            
        Returns:
            Analysis ID if successful, None if failed
        """
        if not self.api_key or self.api_key == "your_virustotal_api_key_here":
            logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                # Submit URL for analysis (VirusTotal expects form data)
                data = {"url": url}
                headers = {
                    "x-apikey": self.api_key
                    # Don't set Content-Type, let httpx handle form data
                }
                response = await client.post(
                    f"{self.base_url}/urls",
                    headers=headers,
                    data=data,  # Use data instead of json for form submission
                    timeout=15.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    analysis_id = result.get("data", {}).get("id")
                    logger.info(f"Successfully submitted URL to VirusTotal: {url}")
                    return analysis_id
                else:
                    logger.warning(f"VirusTotal submission failed: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error submitting URL to VirusTotal: {str(e)}")
            return None
    
    async def get_analysis_result(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Get analysis result by analysis ID.
        
        Args:
            analysis_id: VirusTotal analysis ID
            
        Returns:
            Analysis result if available, None if not ready
        """
        if not self.api_key or self.api_key == "your_virustotal_api_key_here":
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting VirusTotal analysis result: {str(e)}")
            return None
    
    async def ensure_fresh_analysis(self, url: str) -> str:
        """
        Ensure URL has fresh VirusTotal analysis - always triggers rescan for latest results.
        
        Args:
            url: URL to analyze
            
        Returns:
            VirusTotal analysis URL (live progress or final results)
        """
        url_id = self._get_url_id(url)
        
        # Check if analysis already exists
        existing_analysis = await self.check_url_analysis(url)
        
        if existing_analysis:
            # URL exists - request fresh rescan for updated results
            logger.info(f"Requesting fresh VirusTotal rescan for: {url}")
            analysis_id = await self.rescan_url(url)
            
            if analysis_id:
                # Return live analysis URL for rescan progress
                return f"https://www.virustotal.com/gui/url-analysis/{analysis_id}"
            else:
                # Fallback to existing results if rescan fails
                return f"https://www.virustotal.com/gui/url/{url_id}"
        else:
            # URL not analyzed before - submit for new analysis
            logger.info(f"Submitting new URL for VirusTotal analysis: {url}")
            analysis_id = await self.submit_url_for_analysis(url)
            
            if analysis_id:
                # Return live analysis URL for new scan progress
                return f"https://www.virustotal.com/gui/url-analysis/{analysis_id}"
            else:
                # Fallback to static URL if submission fails
                return f"https://www.virustotal.com/gui/url/{url_id}"


# Global instance
virustotal_service = VirusTotalService()