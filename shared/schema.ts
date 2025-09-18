import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const alerts = pgTable("alerts", {
  id: varchar("id").primaryKey(),
  type: text("type").notNull(),
  severity: text("severity").notNull(), // Critical, High, Medium, Low
  source: text("source").notNull(),
  timestamp: timestamp("timestamp").notNull().default(sql`now()`),
  status: text("status").notNull().default("New"), // New, Triaging, Investigating, Resolved
  confidence: integer("confidence"),
  affectedAssets: integer("affected_assets"),
  businessImpact: text("business_impact"), // High, Medium, Low
  assignee: text("assignee"),
  aiTriaged: boolean("ai_triaged").default(false),
  title: text("title").notNull(),
  description: text("description"),
  metadata: jsonb("metadata")
});

export const threatIntelligence = pgTable("threat_intelligence", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  alertId: varchar("alert_id").references(() => alerts.id),
  maliciousScore: integer("malicious_score"),
  previousSightings: integer("previous_sightings"),
  threatActor: text("threat_actor"),
  iocs: jsonb("iocs"), // Array of IOC objects
  attribution: jsonb("attribution"),
  createdAt: timestamp("created_at").default(sql`now()`)
});

export const iocs = pgTable("iocs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  type: text("type").notNull(), // ip, domain, url, hash
  value: text("value").notNull(),
  reputation: text("reputation"), // Clean, Suspicious, Malicious
  source: text("source"),
  enrichmentData: jsonb("enrichment_data"),
  alertId: varchar("alert_id").references(() => alerts.id),
  createdAt: timestamp("created_at").default(sql`now()`)
});

export const auditLog = pgTable("audit_log", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timestamp: timestamp("timestamp").default(sql`now()`),
  actor: text("actor").notNull(), // USER, AI, SYSTEM
  action: text("action").notNull(),
  alertId: varchar("alert_id").references(() => alerts.id),
  metadata: jsonb("metadata")
});

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  role: text("role").notNull(), // analyst, manager, executive
  clearanceLevel: integer("clearance_level").default(1)
});

export const correlations = pgTable("correlations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  primaryAlertId: varchar("primary_alert_id").references(() => alerts.id).notNull(),
  relatedAlertId: varchar("related_alert_id").references(() => alerts.id).notNull(),
  correlationType: text("correlation_type").notNull(), // ioc_overlap, time_proximity, source_similarity, threat_actor, campaign
  confidence: integer("confidence").notNull(), // 0-100 correlation confidence score
  correlationData: jsonb("correlation_data"), // Specific details about the correlation
  createdAt: timestamp("created_at").default(sql`now()`)
});

export const insertAlertSchema = createInsertSchema(alerts).omit({
  id: true,
  timestamp: true
});

export const insertThreatIntelSchema = createInsertSchema(threatIntelligence).omit({
  id: true,
  createdAt: true
});

export const insertIOCSchema = createInsertSchema(iocs).omit({
  id: true,
  createdAt: true
});

export const insertAuditLogSchema = createInsertSchema(auditLog).omit({
  id: true,
  timestamp: true
});

export const insertUserSchema = createInsertSchema(users).omit({
  id: true
});

export const insertCorrelationSchema = createInsertSchema(correlations).omit({
  id: true,
  createdAt: true
});

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type ThreatIntelligence = typeof threatIntelligence.$inferSelect;
export type InsertThreatIntelligence = z.infer<typeof insertThreatIntelSchema>;
export type IOC = typeof iocs.$inferSelect;
export type InsertIOC = z.infer<typeof insertIOCSchema>;
export type AuditLog = typeof auditLog.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Correlation = typeof correlations.$inferSelect;
export type InsertCorrelation = z.infer<typeof insertCorrelationSchema>;
