import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { storage } from "./storage";
import { threatIntelManager } from "./threat-feeds";
import { siemIntegration } from "./siem-integration";
import { playbookEngine } from "./playbook-engine";
import { emailAnalysisService } from "./email-analysis";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      
      // Only log response bodies in development to prevent sensitive data leaks
      if (process.env.NODE_ENV === "development" && capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);
  
  // Initialize sample data for development
  if (app.get("env") === "development") {
    try {
      await (storage as any).initializeSampleData?.();
      log("Sample data initialized");
      
      // Initialize sample playbooks
      await playbookEngine.initializeSamplePlaybooks();
      log("Sample playbooks initialized");
    } catch (error) {
      log("Error initializing sample data:", error);
    }
  }

  // Start real-time threat intelligence feeds
  try {
    await threatIntelManager.startLiveFeedUpdates();
    log("Real-time threat intelligence feeds started");
  } catch (error) {
    log("Error starting threat intelligence feeds:", error);
  }

  // Initialize SIEM platform integrations
  try {
    await siemIntegration.connectToAllPlatforms();
    log("SIEM platform integrations started");
  } catch (error) {
    log("Error starting SIEM integrations:", error);
  }

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen(port, "127.0.0.1", () => {
    log(`serving on port ${port}`);
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT. Shutting down gracefully...');
    emailAnalysisService.cleanup();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('🛑 Received SIGTERM. Shutting down gracefully...');
    emailAnalysisService.cleanup();
    process.exit(0);
  });
})();
