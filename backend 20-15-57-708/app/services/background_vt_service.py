"""
Background VirusTotal submission service for automatic URL scanning.
"""

import asyncio
import hashlib
from typing import Set
from ..services.virustotal_service import virustotal_service
from ..utils.logging import get_logger

logger = get_logger(__name__)


class BackgroundVTService:
    """Background service for automatic VirusTotal URL submission."""
    
    def __init__(self):
        self.submitted_urls: Set[str] = set()
        self.submission_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
    
    def _get_url_id(self, url: str) -> str:
        """Generate VirusTotal URL ID from URL using base64 encoding."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    async def submit_url_background(self, url: str) -> str:
        """
        Submit URL to VirusTotal in background and return GUI link immediately.
        
        Args:
            url: URL to submit
            
        Returns:
            VirusTotal GUI URL (available immediately)
        """
        url_id = self._get_url_id(url)
        gui_url = f"https://www.virustotal.com/gui/url/{url_id}"
        
        # Check if we've already submitted this URL
        if url in self.submitted_urls:
            logger.debug(f"URL already submitted: {url}")
            return gui_url
        
        # Add to submission queue for background processing
        try:
            await self.submission_queue.put(url)
            self.submitted_urls.add(url)
            logger.info(f"Queued URL for VirusTotal submission: {url}")
        except Exception as e:
            logger.error(f"Failed to queue URL for submission: {str(e)}")
        
        # Return GUI URL immediately (analysis will be available shortly)
        return gui_url
    
    async def _process_submission_queue(self):
        """Background worker to process URL submissions."""
        while self._running:
            try:
                # Wait for URL with timeout
                url = await asyncio.wait_for(
                    self.submission_queue.get(), 
                    timeout=5.0
                )
                
                # Check if URL already has analysis
                existing_analysis = await virustotal_service.check_url_analysis(url)
                
                if existing_analysis:
                    logger.info(f"URL already analyzed in VirusTotal: {url}")
                else:
                    # Submit for new analysis
                    analysis_id = await virustotal_service.submit_url_for_analysis(url)
                    
                    if analysis_id:
                        logger.info(f"Successfully submitted URL to VirusTotal: {url}")
                    else:
                        logger.warning(f"Failed to submit URL to VirusTotal: {url}")
                
                # Mark task as done
                self.submission_queue.task_done()
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(1)
                
            except asyncio.TimeoutError:
                # No URLs in queue, continue waiting
                continue
            except Exception as e:
                logger.error(f"Error processing VirusTotal submission: {str(e)}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def start(self):
        """Start the background submission service."""
        if self._running:
            return
        
        self._running = True
        logger.info("Starting VirusTotal background submission service")
        
        # Start background worker
        asyncio.create_task(self._process_submission_queue())
    
    async def stop(self):
        """Stop the background submission service."""
        self._running = False
        logger.info("Stopping VirusTotal background submission service")
        
        # Wait for remaining submissions to complete
        await self.submission_queue.join()


# Global instance
background_vt_service = BackgroundVTService()