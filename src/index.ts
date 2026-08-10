#!/usr/bin/env bun
import { createDevServer } from "./server.ts";

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(`takosumi-dev-server

Product-neutral local development server for Takosumi public contracts.

Environment:
  TAKOSUMI_DEV_HOST                Bind host (default: 127.0.0.1)
  TAKOSUMI_DEV_PORT                Bind port (default: 8792)
  TAKOSUMI_DEV_ORIGIN              Public origin (defaults to bind host/port)
  TAKOSUMI_DEV_TOKEN               Bootstrap API token
  TAKOSUMI_DEV_STATE_FILE          Optional JSON fixture/persistence file
  TAKOSUMI_DEV_ALLOWED_REDIRECTS   Comma-separated exact OAuth redirect URIs
  TAKOSUMI_DEV_ALLOWED_ORIGINS     Comma-separated exact CORS origins
  TAKOSUMI_DEV_ALLOW_NON_LOOPBACK  Set to 1 to bind/expose beyond loopback
`);
  process.exit(0);
}

const hostname = process.env.TAKOSUMI_DEV_HOST?.trim() || "127.0.0.1";
const port = parsePort(process.env.TAKOSUMI_DEV_PORT);
const allowNonLoopback = process.env.TAKOSUMI_DEV_ALLOW_NON_LOOPBACK === "1";
const origin = process.env.TAKOSUMI_DEV_ORIGIN?.trim() || `http://${hostForUrl(hostname)}:${port}`;
const server = await createDevServer({
  origin,
  ...(process.env.TAKOSUMI_DEV_STATE_FILE?.trim() ? { stateFile: process.env.TAKOSUMI_DEV_STATE_FILE.trim() } : {}),
  ...(process.env.TAKOSUMI_DEV_TOKEN?.trim() ? { bootstrapToken: process.env.TAKOSUMI_DEV_TOKEN.trim() } : {}),
  ...(csv(process.env.TAKOSUMI_DEV_ALLOWED_REDIRECTS).length > 0 ? { allowedRedirectUris: csv(process.env.TAKOSUMI_DEV_ALLOWED_REDIRECTS) } : {}),
  ...(csv(process.env.TAKOSUMI_DEV_ALLOWED_ORIGINS).length > 0 ? { allowedOrigins: csv(process.env.TAKOSUMI_DEV_ALLOWED_ORIGINS) } : {}),
  allowNonLoopback,
});

if (!allowNonLoopback && !isLoopback(hostname)) {
  throw new Error("non-loopback bind requires TAKOSUMI_DEV_ALLOW_NON_LOOPBACK=1");
}

Bun.serve({ hostname, port, fetch: server.fetch });

console.log(`Takosumi development server listening on ${server.origin}`);
console.log(`Bootstrap token: ${server.bootstrapToken}`);
console.log("Seeded principal: developer@local.test (automatic OIDC login)");
console.log("Development fixture only; it is not a production lifecycle authority.");

function parsePort(raw: string | undefined): number {
  if (!raw?.trim()) return 8792;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new TypeError("TAKOSUMI_DEV_PORT must be an integer from 1 to 65535");
  return value;
}

function csv(raw: string | undefined): string[] {
  return [...new Set((raw ?? "").split(",").map((entry) => entry.trim()).filter(Boolean))];
}

function hostForUrl(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function isLoopback(host: string): boolean {
  const normalized = host.replace(/^\[|\]$/gu, "").toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}
