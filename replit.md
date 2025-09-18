# Overview

Cyber-Sentinel Workbench is a comprehensive cybersecurity threat intelligence and alert management platform built with modern web technologies. The application provides security analysts, managers, and executives with tools to investigate, triage, and manage security alerts through an intuitive dashboard interface. The platform features real-time alert monitoring, IOC (Indicator of Compromise) enrichment capabilities, threat intelligence integration, and role-based views for different user types.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Framework**: React 18 with TypeScript for type safety and modern development
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: TanStack Query for server state management and caching
- **UI Framework**: Radix UI primitives with shadcn/ui components for accessible, customizable interface
- **Styling**: Tailwind CSS with CSS variables for theming and dark mode support
- **Build Tool**: Vite for fast development and optimized production builds

## Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ESM modules for consistency with frontend
- **API Design**: RESTful API structure with dedicated route handlers
- **Storage**: In-memory storage implementation with interface abstraction for future database integration
- **Development**: Hot module replacement and middleware-based request logging

## Data Storage Solutions
- **ORM**: Drizzle ORM with PostgreSQL dialect configuration
- **Database**: Neon serverless PostgreSQL (configured but not yet implemented)
- **Schema**: Comprehensive database schema including alerts, threat intelligence, IOCs, audit logs, and users
- **Migration**: Drizzle Kit for schema migrations and database management
- **Current State**: Memory-based storage for development, designed for easy PostgreSQL migration

## Authentication and Authorization
- **Session Management**: Express sessions with connect-pg-simple for PostgreSQL session storage
- **Role-Based Access**: Three user roles (analyst, manager, executive) with different dashboard views
- **Security**: Built-in CORS support and security middleware ready for implementation

## External Dependencies
- **Database**: Neon Database (@neondatabase/serverless) for serverless PostgreSQL
- **UI Components**: Comprehensive Radix UI component library for accessibility
- **Development Tools**: Replit-specific plugins for development environment integration
- **Validation**: Zod for runtime type validation and schema parsing
- **Date Handling**: date-fns for date manipulation and formatting
- **Carousel**: Embla Carousel for interactive UI components

## Key Features
- **Real-time Monitoring**: Live alert updates with automatic refresh mechanisms
- **IOC Analysis**: Built-in IOC parsing and enrichment capabilities for threat investigation
- **Multi-role Interface**: Tailored dashboards for analysts, managers, and executives
- **Audit Logging**: Comprehensive activity tracking and audit trail
- **Threat Intelligence**: Integration-ready threat intelligence enrichment system
- **Responsive Design**: Mobile-friendly interface with adaptive layouts

The architecture follows a modern full-stack approach with clear separation of concerns, type safety throughout, and scalability considerations for future enhancements like real database integration and advanced threat intelligence feeds.