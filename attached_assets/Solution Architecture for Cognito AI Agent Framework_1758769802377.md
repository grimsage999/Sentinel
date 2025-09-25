# Solution Architecture for Cognito AI Agent Framework

## 1. Introduction

This document outlines a high-level solution architecture for integrating an intelligent AI agent framework with the existing Cognito application. The goal is to enhance Cognito's capabilities for autonomous detection, analysis, and response to cybersecurity threats by dynamically sourcing and processing threat intelligence from web sources, all while operating efficiently under a 200-credit budget.

## 2. Cognito Application Overview

Cognito (formerly Sentinel) is a web-based tool designed to provide rapid, AI-powered analysis of phishing emails for SOC analysts. It consists of:

- **Frontend**: A React 18+ application with TypeScript, Tailwind CSS, and Vite.
- **Backend**: A FastAPI (Python) application utilizing Pydantic, integrated with LLM providers (OpenAI, Anthropic, Google) and VirusTotal API.

The core functionality revolves around an `/api/analyze` endpoint that takes raw email content and returns a comprehensive analysis, including intent classification, deception indicators, risk scoring, and IOC extraction.

## 3. AI Agent Framework Integration Strategy

The AI agent framework will be integrated as an extension to Cognito's backend services, leveraging its existing LLM integration, API structure, and data handling capabilities. The primary focus will be on enhancing the `llm_analyzer` service and introducing new services for autonomous web intelligence gathering.

## 4. High-Level Architecture

### A. Core Components

1.  **Threat Intelligence Harvester (New Service)**:
    *   **Purpose**: Autonomously discover, monitor, and collect cybersecurity information from various web sources.
    *   **Capabilities**: Web scraping (rate-limited), API integration (VirusTotal, AbuseIPDB, etc.), RSS/Feed processing, social media monitoring (if feasible within credit limits).
    *   **Output**: Raw threat intelligence data (e.g., IOCs, vulnerability reports, security advisories).
    *   **Integration Point**: This service will run independently or be triggered periodically by a scheduler within the Cognito backend environment.

2.  **Threat Intelligence Processor (New Service)**:
    *   **Purpose**: Process raw threat intelligence, extract structured data, validate credibility, and maintain a dynamic knowledge base.
    *   **Capabilities**: Data normalization, entity extraction, source credibility scoring, information freshness validation.
    *   **Output**: Structured threat intelligence data, updated knowledge base.
    *   **Integration Point**: Consumes data from the Threat Intelligence Harvester and feeds into the existing `llm_analyzer` or a new dedicated threat correlation engine.

3.  **Enhanced LLM Analyzer (Modification to Existing Service)**:
    *   **Purpose**: Utilize the newly processed threat intelligence to enrich existing email analysis and provide more contextual responses.
    *   **Modifications**: The `LLMAnalyzer` will be updated to query the dynamic knowledge base (managed by the Threat Intelligence Processor) during email analysis. This will allow for real-time correlation of email IOCs with known threats.
    *   **Integration Point**: Directly within the `analyze_email` method of the `LLMAnalyzer` service.

4.  **Response Generation & Action Orchestrator (New Service/Extension)**:
    *   **Purpose**: Generate tailored mitigation strategies and orchestrate automated actions based on the enhanced threat analysis.
    *   **Capabilities**: Contextual response generation, alert generation, evidence collection (e.g., logging analysis results), containment procedure suggestions.
    *   **Integration Point**: Extends the output of the `LLMAnalyzer` to format responses for the frontend and potentially trigger external alerts or actions.

### B. Data Flow

1.  **Scheduled Harvesting**: The Threat Intelligence Harvester runs periodically, collecting data from configured sources.
2.  **Processing & Knowledge Base Update**: Collected data is fed into the Threat Intelligence Processor, which cleans, structures, and stores it in a persistent knowledge base (e.g., a simple database or file-based storage for credit efficiency).
3.  **Email Analysis Request**: A user submits an email to Cognito's `/api/analyze` endpoint.
4.  **Enhanced LLM Analysis**: The `LLMAnalyzer` processes the email. Before or during LLM calls, it queries the knowledge base for relevant threat intelligence (e.g., checking if extracted IOCs are known malicious entities).
5.  **Contextual Response**: The LLM generates an analysis enriched with real-time threat intelligence. The Response Generation & Action Orchestrator formats this into a user-friendly output and suggests actions.
6.  **Frontend Display**: The enhanced analysis and response are displayed in the Cognito frontend.

## 5. Integration Points within Cognito Backend

-   **`backend/app/main.py`**: The main FastAPI application. New background tasks for the Harvester and Processor can be initiated here during `lifespan` events.
-   **`backend/app/api/routes/analysis.py`**: The `/api/analyze` endpoint. This is where the `LLMAnalyzer` is called. The enhanced analysis logic will reside here or within the `LLMAnalyzer` itself.
-   **`backend/app/services/llm_analyzer.py`**: This service will be modified to incorporate queries to the new threat intelligence knowledge base.
-   **`backend/app/core/config.py`**: New environment variables will be added for configuring threat intelligence sources, API keys for new services (e.g., AbuseIPDB), and scheduling parameters.
-   **New `backend/app/services/threat_intelligence/` directory**: This directory will house the new Harvester, Processor, and knowledge base management services.

## 6. Credit Optimization Considerations

To stay under 200 credits, the following strategies will be employed:

-   **Selective Data Sources**: Prioritize free and easily accessible threat intelligence feeds (e.g., public RSS feeds, open-source intelligence platforms) over premium APIs.
-   **Rate Limiting & Caching**: Implement aggressive caching for threat intelligence data and strict rate limiting for external API calls and web scraping to minimize external service usage.
-   **Efficient LLM Usage**: Optimize prompts to be concise and effective, minimizing token usage. Leverage the existing LLM integration rather than introducing new LLM calls for every step of threat intelligence processing.
-   **Minimalist Knowledge Base**: Start with a simple, file-based or SQLite database for the knowledge base to avoid complex and costly database services.
-   **Asynchronous Processing**: Utilize FastAPI's asynchronous capabilities to handle background tasks for harvesting and processing without blocking the main API, ensuring efficient resource use.
-   **Incremental Development**: Implement core features first, then iteratively add more sophisticated capabilities if credit budget allows.

This architecture provides a clear path for integrating the AI agent framework into Cognito, focusing on leveraging existing strengths and optimizing for credit efficiency. The next steps will involve detailing the implementation plan and specific code modifications.



## 7. Implementation Plan (Under 200 Credits)

This implementation plan prioritizes core functionalities and credit efficiency. It assumes a phased approach, focusing on delivering maximum value within the specified credit budget.

### Phase 1: Foundation for Threat Intelligence (Estimated Credits: 50)

1.  **Create `backend/app/services/threat_intelligence/` directory and `__init__.py`**: Establish the module structure.
2.  **Implement `ThreatIntelligenceHarvester` (Basic)**:
    *   **Objective**: Collect basic, free threat intelligence feeds.
    *   **Details**: Start with RSS/Atom feed parsing for security blogs (e.g., CISA, US-CERT, reputable security news sites). Use a simple `requests` and `feedparser` library. Avoid complex web scraping initially.
    *   **Integration**: Implement a background task in `backend/app/main.py` (within `lifespan`) to run the harvester periodically (e.g., once every 6-12 hours).
    *   **Output**: Store raw feed entries in a local SQLite database (`threat_intel.db`) or as JSON files in a designated directory.
3.  **Implement `ThreatIntelligenceProcessor` (Basic)**:
    *   **Objective**: Process raw threat data and extract key IOCs (URLs, IPs, domains).
    *   **Details**: Use simple regex or string matching to extract IOCs from the harvested text. Focus on common patterns. No advanced NLP initially.
    *   **Integration**: Run as part of the harvester's pipeline or as a separate background task after harvesting.
    *   **Output**: Store extracted and normalized IOCs in the same `threat_intel.db` (e.g., in a separate table) or a structured JSON file.
4.  **Update `backend/app/core/config.py`**: Add settings for `THREAT_INTEL_SOURCES` (list of RSS URLs), `HARVEST_INTERVAL_HOURS`, and `SQLITE_DB_PATH`.

### Phase 2: Enhanced LLM Analysis with Context (Estimated Credits: 80)

1.  **Modify `LLMAnalyzer` (`backend/app/services/llm_analyzer.py`)**:
    *   **Objective**: Integrate the processed threat intelligence into the email analysis.
    *   **Details**: Before making the LLM call in `analyze_email`, query the `threat_intel.db` (or JSON files) to check if any IOCs extracted from the email (`iocs` parameter) are present in the harvested threat intelligence. If a match is found, include this context in the prompt sent to the LLM.
    *   **Prompt Enhancement**: Add a section to the `PromptBuilder` (`backend/app/services/prompt_builder.py`) to include 


relevant threat intelligence findings (e.g., "The URL `malicious.com` was identified in a recent phishing campaign reported by CISA on 2025-09-20.").
2.  **Implement `ThreatIntelService` (New Service)**:
    *   **Objective**: Provide an interface to query the local threat intelligence knowledge base.
    *   **Details**: A simple Python class that interacts with the `threat_intel.db` (or JSON files) to retrieve IOCs and associated context.
    *   **Integration**: Injected as a dependency into `LLMAnalyzer`.

### Phase 3: Basic Response Generation & Logging (Estimated Credits: 40)

1.  **Extend `AnalysisResult` Model (`backend/app/models/analysis_models.py`)**:
    *   **Objective**: Add fields for recommended mitigation strategies and incident response steps.
    *   **Details**: Include new fields like `mitigation_strategies: List[str]` and `incident_response_steps: List[str]`.
2.  **Modify `LLMAnalyzer` for Response Generation**:
    *   **Objective**: Instruct the LLM to generate basic mitigation and response guidance based on its analysis and the enriched threat intelligence.
    *   **Details**: Update the prompt to ask the LLM for these specific outputs in a structured format (e.g., JSON fields).
3.  **Enhanced Logging**: Ensure that the new threat intelligence context and generated response elements are included in the application logs for audit and review.

### Phase 4: Testing and Refinement (Estimated Credits: 30)

1.  **Unit and Integration Tests**: Write tests for the new Harvester, Processor, and the modified `LLMAnalyzer`.
2.  **Performance Testing**: Monitor resource usage (CPU, memory, API calls) to ensure adherence to the 200-credit budget.
3.  **Refinement**: Based on testing, optimize prompts, adjust harvesting frequency, and fine-tune IOC extraction logic.

## 8. Credit Breakdown Summary

*   **Phase 1 (Foundation)**: ~50 credits
*   **Phase 2 (Enhanced LLM Analysis)**: ~80 credits
*   **Phase 3 (Basic Response Generation)**: ~40 credits
*   **Phase 4 (Testing & Refinement)**: ~30 credits
*   **Total Estimated Credits**: ~200 credits

This plan focuses on credit-efficient implementation by prioritizing free data sources, aggressive caching, and leveraging existing LLM integrations. Further enhancements (e.g., advanced web scraping, vector databases, social media monitoring) would require additional credit allocation.

