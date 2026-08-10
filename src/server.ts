import { DevOidcProvider } from "./oidc.ts";
import { DevStore, id, slug } from "./store.ts";
import { TAKOSUMI_API_VERSION, type DevInterface, type DevInterfaceBinding } from "./types.ts";

const DEFAULT_BOOTSTRAP_TOKEN = "takosumi-dev-token";
const MAX_BODY_BYTES = 1024 * 1024;
const HANDLE_PATTERN = /^[a-z0-9][a-z0-9-]{1,38}$/u;
const NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u;
const PERMISSION_PATTERN = /^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/u;

export interface DevServerOptions {
  readonly origin?: string;
  readonly stateFile?: string;
  readonly bootstrapToken?: string;
  readonly allowedRedirectUris?: readonly string[];
  readonly allowedOrigins?: readonly string[];
  readonly allowNonLoopback?: boolean;
}

export interface TakosumiDevServer {
  readonly origin: string;
  readonly bootstrapToken: string;
  readonly store: DevStore;
  fetch(request: Request): Promise<Response>;
}

export async function createDevServer(options: DevServerOptions = {}): Promise<TakosumiDevServer> {
  const origin = normalizeOrigin(options.origin ?? "http://127.0.0.1:8792", options.allowNonLoopback ?? false);
  const bootstrapToken = options.bootstrapToken?.trim() || DEFAULT_BOOTSTRAP_TOKEN;
  if (/\s/u.test(bootstrapToken) || bootstrapToken.length > 4_096) throw new TypeError("bootstrapToken must be a bounded token without whitespace");
  if (!isLoopbackHostname(new URL(origin).hostname) && bootstrapToken.length < 32) {
    throw new TypeError("non-loopback exposure requires an explicit bootstrapToken of at least 32 characters");
  }
  const store = await DevStore.open(options.stateFile);
  const oidc = await DevOidcProvider.create({ origin, principal: store.principal, ...(options.allowedRedirectUris ? { allowedRedirectUris: options.allowedRedirectUris } : {}) });
  const allowedOrigins = new Set(options.allowedOrigins ?? []);

  return {
    origin,
    bootstrapToken,
    store,
    async fetch(request: Request): Promise<Response> {
      const requestUrl = new URL(request.url);
      if (request.method === "OPTIONS") return cors(request, new Response(null, { status: 204 }), allowedOrigins);
      let response: Response;
      try {
        response = await route(request, requestUrl, { origin, bootstrapToken, store, oidc });
      } catch (error) {
        response = error instanceof HttpError
          ? apiError(error.code, error.message, error.status)
          : apiError("internal_error", error instanceof Error ? error.message : "internal error", 500);
      }
      return cors(request, secure(response), allowedOrigins);
    },
  };
}

interface RouteContext {
  readonly origin: string;
  readonly bootstrapToken: string;
  readonly store: DevStore;
  readonly oidc: DevOidcProvider;
}

async function route(request: Request, url: URL, context: RouteContext): Promise<Response> {
  if (request.method === "GET" && url.pathname === "/healthz") {
    return json({ ok: true, product: "takosumi-dev-server", authority: "development-only" });
  }
  if (request.method === "GET" && url.pathname === "/.well-known/takosumi") {
    return json(wellKnown(context.origin));
  }
  if (request.method === "GET" && url.pathname === "/v1/capabilities") {
    return json(capabilities());
  }
  if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") return json(context.oidc.discovery());
  if (request.method === "GET" && url.pathname === "/oauth/jwks") return json(context.oidc.jwks());
  if (request.method === "GET" && url.pathname === "/oauth/authorize") return await context.oidc.authorize(url);
  if (request.method === "POST" && url.pathname === "/oauth/token") return await context.oidc.token(request);
  if (request.method === "GET" && url.pathname === "/oauth/userinfo") return await context.oidc.userinfo(request);
  if (request.method === "POST" && url.pathname === "/oauth/revoke") return await context.oidc.revoke(request);
  if (request.method === "POST" && url.pathname === "/oauth/introspect") return await context.oidc.introspect(request);

  const actor = authenticate(request, context);
  if (!actor) return apiError("unauthenticated", "Bearer authentication is required", 401);

  if (url.pathname === "/api/v1/workspaces" && request.method === "GET") {
    return json({ workspaces: context.store.listWorkspaces(actor.subject) });
  }
  if (url.pathname === "/api/v1/workspaces" && request.method === "POST") {
    const body = await readObject(request);
    const handle = requiredString(body.handle, "handle", 39);
    const displayName = requiredString(body.displayName, "displayName", 128);
    if (!HANDLE_PATTERN.test(handle)) return apiError("invalid_request", "handle is invalid", 400);
    if (context.store.listWorkspaces(actor.subject).some((entry) => entry.handle === handle)) return apiError("conflict", "Workspace handle already exists", 409);
    const type = body.type === "personal" ? "personal" : "organization";
    return json({ workspace: await context.store.createWorkspace(actor.subject, { handle, displayName, type }) }, 201);
  }

  const workspaceMatch = /^\/api\/v1\/workspaces\/([^/]+)$/u.exec(url.pathname);
  if (workspaceMatch && request.method === "GET") {
    const workspaceId = decode(workspaceMatch[1]!);
    const denied = workspaceAccess(context.store, actor.subject, workspaceId);
    if (denied) return denied;
    return json({ workspace: context.store.workspace(workspaceId) });
  }

  const capsulesMatch = /^\/api\/v1\/workspaces\/([^/]+)\/capsules$/u.exec(url.pathname);
  if (capsulesMatch) {
    const workspaceId = decode(capsulesMatch[1]!);
    const denied = workspaceAccess(context.store, actor.subject, workspaceId);
    if (denied) return denied;
    if (request.method === "GET") return json({ capsules: context.store.listCapsules(workspaceId).filter((entry) => url.searchParams.get("includeDestroyed") === "true" || entry.status !== "destroyed") });
    if (request.method === "POST") {
      const body = await readObject(request);
      const name = requiredString(body.name, "name", 128);
      const sourceId = requiredString(body.sourceId, "sourceId", 256);
      const source = context.store.source(sourceId);
      if (!source || source.workspaceId !== workspaceId) return apiError("invalid_request", "sourceId does not belong to Workspace", 400);
      const capsule = await context.store.createCapsule(workspaceId, {
        name,
        sourceId,
        ...(optionalString(body.environment, 64) ? { environment: optionalString(body.environment, 64)! } : {}),
        ...(optionalString(body.installConfigId, 256) ? { installConfigId: optionalString(body.installConfigId, 256)! } : {}),
      });
      return json({ capsule }, 201);
    }
  }

  const capsuleMatch = /^\/api\/v1\/capsules\/([^/]+)$/u.exec(url.pathname);
  if (capsuleMatch && request.method === "GET") {
    const capsule = context.store.capsule(decode(capsuleMatch[1]!));
    if (!capsule) return apiError("not_found", "Capsule not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, capsule.workspaceId);
    return denied ?? json({ capsule });
  }

  if (url.pathname === "/api/v1/sources") {
    const workspaceId = url.searchParams.get("workspaceId") ?? "";
    if (request.method === "GET") {
      const denied = workspaceAccess(context.store, actor.subject, workspaceId);
      return denied ?? json({ sources: context.store.listSources(workspaceId) });
    }
    if (request.method === "POST") {
      const body = await readObject(request);
      const bodyWorkspaceId = requiredString(body.workspaceId, "workspaceId", 256);
      const denied = workspaceAccess(context.store, actor.subject, bodyWorkspaceId);
      if (denied) return denied;
      const source = await context.store.createSource(bodyWorkspaceId, {
        name: requiredString(body.name, "name", 128),
        url: absoluteHttpUrl(body.url, "url"),
        defaultRef: optionalString(body.defaultRef, 256) ?? "main",
        defaultPath: optionalString(body.defaultPath, 1_024) ?? ".",
      });
      return json({ source }, 201);
    }
  }

  const sourceMatch = /^\/api\/v1\/sources\/([^/]+)$/u.exec(url.pathname);
  if (sourceMatch) {
    const source = context.store.source(decode(sourceMatch[1]!));
    if (!source) return apiError("not_found", "Source not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, source.workspaceId);
    if (denied) return denied;
    if (request.method === "GET") return json({ source });
    if (request.method === "PATCH") {
      const body = await readObject(request);
      const updated = await context.store.updateSource(source.id, {
        ...(optionalString(body.defaultRef, 256) ? { defaultRef: optionalString(body.defaultRef, 256)! } : {}),
        ...(optionalString(body.defaultPath, 1_024) ? { defaultPath: optionalString(body.defaultPath, 1_024)! } : {}),
      });
      return json({ source: updated });
    }
  }

  const syncMatch = /^\/api\/v1\/sources\/([^/]+)\/sync$/u.exec(url.pathname);
  if (syncMatch && request.method === "POST") {
    const source = context.store.source(decode(syncMatch[1]!));
    if (!source) return apiError("not_found", "Source not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, source.workspaceId);
    if (denied) return denied;
    const run = await context.store.createRun({ workspaceId: source.workspaceId, type: "source_sync", status: "succeeded", requiresApproval: false, summary: "Development fixture source synchronized", createdBy: actor.subject });
    return json({ run }, 201);
  }

  const planMatch = /^\/api\/v1\/capsules\/([^/]+)\/plan$/u.exec(url.pathname);
  if (planMatch && request.method === "POST") {
    const capsule = context.store.capsule(decode(planMatch[1]!));
    if (!capsule) return apiError("not_found", "Capsule not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, capsule.workspaceId);
    if (denied) return denied;
    const run = await context.store.createRun({ workspaceId: capsule.workspaceId, capsuleId: capsule.id, type: "plan", status: "succeeded", requiresApproval: false, summary: "Development fixture plan; no infrastructure was changed", createdBy: actor.subject });
    return json({ run }, 201);
  }

  const runMatch = /^\/api\/v1\/runs\/([^/]+)$/u.exec(url.pathname);
  if (runMatch && request.method === "GET") {
    const run = context.store.run(decode(runMatch[1]!));
    if (!run) return apiError("not_found", "Run not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, run.workspaceId);
    return denied ?? json({ run });
  }

  const runActionMatch = /^\/api\/v1\/runs\/([^/]+)\/(apply|approve)$/u.exec(url.pathname);
  if (runActionMatch && request.method === "POST") {
    const run = context.store.run(decode(runActionMatch[1]!));
    if (!run) return apiError("not_found", "Run not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, run.workspaceId);
    if (denied) return denied;
    if (runActionMatch[2] === "apply" && run.capsuleId) await context.store.activateCapsule(run.capsuleId);
    return json({ run: { ...run, status: "succeeded", requiresApproval: false } });
  }

  if (url.pathname === "/v1/interfaces") {
    if (request.method === "GET") return listInterfaces(url, actor, context);
    if (request.method === "POST") return await createInterface(request, actor, context);
  }

  const interfaceMatch = /^\/v1\/interfaces\/([^/]+)$/u.exec(url.pathname);
  if (interfaceMatch && request.method === "GET") {
    const iface = context.store.interface(decode(interfaceMatch[1]!));
    if (!iface) return apiError("not_found", "Interface not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, iface.metadata.workspaceId);
    return denied ?? json(iface);
  }

  const bindingsMatch = /^\/v1\/interfaces\/([^/]+)\/bindings$/u.exec(url.pathname);
  if (bindingsMatch) {
    const iface = context.store.interface(decode(bindingsMatch[1]!));
    if (!iface) return apiError("not_found", "Interface not found", 404);
    const denied = workspaceAccess(context.store, actor.subject, iface.metadata.workspaceId);
    if (denied) return denied;
    if (request.method === "GET") {
      const permission = url.searchParams.get("permission");
      return json({ bindings: context.store.listBindings(iface.metadata.id).filter((binding) => binding.status.phase === "Ready" && (!permission || binding.spec.permissions.includes(permission)) && (actor.bootstrap || binding.spec.subjectRef.id === actor.publicSubject)) });
    }
    if (request.method === "POST") {
      if (!actor.bootstrap) return apiError("forbidden", "bootstrap token is required to create bindings", 403);
      const body = await readObject(request);
      const subjectRef = record(body.subjectRef, "subjectRef");
      const permissions = stringArray(body.permissions, "permissions", 64);
      if (!permissions.every((permission) => PERMISSION_PATTERN.test(permission))) return apiError("invalid_request", "permission token is invalid", 400);
      const now = new Date().toISOString();
      const binding: DevInterfaceBinding = {
        apiVersion: TAKOSUMI_API_VERSION,
        kind: "InterfaceBinding",
        metadata: { id: id("ifb"), workspaceId: iface.metadata.workspaceId, generation: 1, createdAt: now, updatedAt: now },
        spec: {
          interfaceId: iface.metadata.id,
          subjectRef: {
            kind: subjectKind(subjectRef.kind),
            id: requiredString(subjectRef.id, "subjectRef.id", 256),
          },
          permissions,
          delivery: { type: optionalString(record(body.delivery, "delivery").type, 128) ?? "none" },
        },
        status: { phase: "Ready", observedInterfaceRevision: iface.status.resolvedRevision },
      };
      return json(await context.store.createBinding(binding), 201);
    }
  }

  const tokenMatch = /^\/v1\/interfaces\/([^/]+)\/token$/u.exec(url.pathname);
  if (tokenMatch && request.method === "POST") {
    if (actor.bootstrap) return apiError("forbidden", "runtime OIDC token is required", 403);
    const iface = context.store.interface(decode(tokenMatch[1]!));
    if (!iface) return apiError("not_found", "Interface not found", 404);
    const body = await readObject(request);
    const permission = requiredString(body.permission, "permission", 256);
    const binding = context.store.listBindings(iface.metadata.id).find((entry) => entry.status.phase === "Ready" && entry.spec.subjectRef.kind === "Principal" && entry.spec.subjectRef.id === actor.publicSubject && entry.spec.permissions.includes(permission));
    if (!binding) return apiError("forbidden", "no Ready InterfaceBinding grants this permission", 403);
    const resource = iface.status.resourceUri;
    if (!resource) return apiError("not_ready", "Interface has no resolved resource URI", 409);
    const expiresIn = 60;
    return json({ access_token: randomToken(), token_type: "Bearer", expires_in: expiresIn, expires_at: new Date(Date.now() + expiresIn * 1_000).toISOString(), scope: permission, resource }, 200, { "cache-control": "no-store" });
  }

  const uiSurfacesMatch = /^\/api\/v1\/workspaces\/([^/]+)\/ui-surfaces$/u.exec(url.pathname);
  if (uiSurfacesMatch && request.method === "GET") {
    const workspaceId = decode(uiSurfacesMatch[1]!);
    const denied = workspaceAccess(context.store, actor.subject, workspaceId);
    if (denied) return denied;
    const interfaces = context.store.listInterfaces(workspaceId).filter((iface) => iface.spec.type === "ui.surface" && iface.status.phase === "Resolved" && context.store.listBindings(iface.metadata.id).some((binding) => binding.status.phase === "Ready" && (actor.bootstrap || binding.spec.subjectRef.id === actor.publicSubject) && binding.spec.permissions.includes("open")));
    return json({ interfaces });
  }

  if (url.pathname.startsWith("/api/v1/") || url.pathname.startsWith("/v1/")) {
    return apiError("not_implemented", "This development server does not implement that Takosumi capability", 501);
  }
  return apiError("not_found", "Route not found", 404);
}

interface Actor {
  readonly subject: string;
  readonly publicSubject: string;
  readonly bootstrap: boolean;
}

function authenticate(request: Request, context: RouteContext): Actor | null {
  const raw = request.headers.get("authorization") ?? "";
  const token = /^Bearer (\S+)$/u.exec(raw)?.[1];
  if (token === context.bootstrapToken) return { subject: context.store.principal.sub, publicSubject: context.store.principal.sub, bootstrap: true };
  const grant = context.oidc.authenticate(request);
  return grant ? { subject: grant.principal.sub, publicSubject: grant.publicSubject, bootstrap: false } : null;
}

function listInterfaces(url: URL, actor: Actor, context: RouteContext): Response {
  const workspaceId = url.searchParams.get("workspaceId") ?? "";
  const denied = workspaceAccess(context.store, actor.subject, workspaceId);
  if (denied) return denied;
  const permission = url.searchParams.get("permission");
  const interfaces = context.store.listInterfaces(workspaceId).filter((iface) =>
    (!url.searchParams.get("type") || iface.spec.type === url.searchParams.get("type")) &&
    (!url.searchParams.get("phase") || iface.status.phase === url.searchParams.get("phase")) &&
    (!url.searchParams.get("ownerKind") || iface.metadata.ownerRef.kind === url.searchParams.get("ownerKind")) &&
    (!url.searchParams.get("ownerId") || iface.metadata.ownerRef.id === url.searchParams.get("ownerId")) &&
    (actor.bootstrap || !permission || context.store.listBindings(iface.metadata.id).some((binding) => binding.status.phase === "Ready" && binding.spec.subjectRef.id === actor.publicSubject && binding.spec.permissions.includes(permission)))
  );
  return json({ interfaces });
}

async function createInterface(request: Request, actor: Actor, context: RouteContext): Promise<Response> {
  if (!actor.bootstrap) return apiError("forbidden", "bootstrap token is required to create Interfaces", 403);
  const body = await readObject(request);
  const workspaceId = requiredString(body.workspaceId, "workspaceId", 256);
  const denied = workspaceAccess(context.store, actor.subject, workspaceId);
  if (denied) return denied;
  const name = requiredString(body.name, "name", 128);
  if (!NAME_PATTERN.test(name)) return apiError("invalid_request", "Interface name is invalid", 400);
  const ownerRef = record(body.ownerRef, "ownerRef");
  const spec = record(body.spec, "spec");
  const access = record(spec.access, "spec.access");
  const now = new Date().toISOString();
  const resourceUri = optionalString(body.resourceUri, 2_048);
  if (resourceUri) absoluteHttpUrl(resourceUri, "resourceUri");
  const iface: DevInterface = {
    apiVersion: TAKOSUMI_API_VERSION,
    kind: "Interface",
    metadata: {
      id: id("ifc"), workspaceId, name,
      ownerRef: { kind: ownerKind(ownerRef.kind), id: requiredString(ownerRef.id, "ownerRef.id", 256) },
      generation: 1, createdAt: now, updatedAt: now,
    },
    spec: {
      type: requiredString(spec.type, "spec.type", 256),
      version: requiredString(spec.version, "spec.version", 64),
      document: spec.document ?? {},
      access: { visibility: visibility(access.visibility), ...(optionalString(access.resourceUriInput, 128) ? { resourceUriInput: optionalString(access.resourceUriInput, 128)! } : {}) },
    },
    status: { phase: "Resolved", observedGeneration: 1, resolvedRevision: 1, ...(resourceUri ? { resourceUri } : {}) },
  };
  return json(await context.store.createInterface(iface), 201);
}

function wellKnown(origin: string): Record<string, unknown> {
  return {
    product: "takosumi", name: "Takosumi development server", auth: { oidc: true, password: false }, apiBaseUrl: `${origin}/api/v1`, api_versions: [TAKOSUMI_API_VERSION],
    features: { stacks: false, resource_shapes: false, opentofu_runner: false, oidc: true, workload_identity: false, compat_framework: false, compatibility_profiles: [], interfaces: true },
    endpoints: { api: `${origin}/api`, capabilities: `${origin}/v1/capabilities`, oidc_issuer: origin },
  };
}

function capabilities(): Record<string, unknown> {
  return {
    apiVersion: TAKOSUMI_API_VERSION,
    resources: { Stack: false, EdgeWorker: false, ObjectBucket: false, KVStore: false, Queue: false, SQLDatabase: false, ContainerService: false, VectorIndex: false, DurableWorkflow: false, StatefulActorNamespace: false, Schedule: false },
    adapters: { opentofu: false }, compat: { framework: false }, compatibilityProfiles: {},
    identity: { oidc_issuer: true, external_oidc_login: false, workload_identity: false },
    operator: { multi_tenant_workspaces: false, workspace_members: false, runner_pools: false, operator_connections: false, target_catalog: false, db_backed_configuration: false, cli_api_operations: false, usage_showback: false, audit_evidence: false },
    formAvailability: { structured: true, endpoint: "/v1/form-availability", principalScoped: true, readScopesAnyOf: ["forms:read", "resources:read"], commercialFields: false, forms: [] },
    extensions: ["takosumi.interfaces.v1alpha1", "takosumi.dev.fixtures.v1alpha1"],
  };
}

function workspaceAccess(store: DevStore, subject: string, workspaceId: string): Response | null {
  if (!workspaceId || !store.workspace(workspaceId)) return apiError("not_found", "Workspace not found", 404);
  return store.canAccessWorkspace(subject, workspaceId) ? null : apiError("forbidden", "Workspace access denied", 403);
}

async function readObject(request: Request): Promise<Record<string, unknown>> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new HttpError("request_too_large", "request body is too large", 413);
  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_BODY_BYTES) throw new HttpError("request_too_large", "request body is too large", 413);
  let value: unknown;
  try { value = JSON.parse(new TextDecoder().decode(body)); } catch { throw new HttpError("invalid_request", "request body must be JSON", 400); }
  return record(value, "request body");
}

class HttpError extends Error {
  constructor(readonly code: string, message: string, readonly status: number) { super(message); }
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError("invalid_request", `${name} must be an object`, 400);
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, name: string, max: number): string {
  const result = optionalString(value, max);
  if (!result) throw new HttpError("invalid_request", `${name} is required`, 400);
  return result;
}

function optionalString(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const result = value.trim();
  return result && result.length <= max && !/[\u0000-\u001f\u007f]/u.test(result) ? result : null;
}

function stringArray(value: unknown, name: string, max: number): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > max || !value.every((entry) => typeof entry === "string")) throw new HttpError("invalid_request", `${name} must be a bounded string array`, 400);
  return [...new Set(value as string[])];
}

function absoluteHttpUrl(value: unknown, name: string): string {
  const raw = requiredString(value, name, 4_096);
  let url: URL;
  try { url = new URL(raw); } catch { throw new HttpError("invalid_request", `${name} must be an absolute URL`, 400); }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) throw new HttpError("invalid_request", `${name} must be a credential-free HTTP(S) URL`, 400);
  return url.toString();
}

function decode(value: string): string {
  try { return decodeURIComponent(value); } catch { throw new HttpError("invalid_request", "path segment is invalid", 400); }
}

function normalizeOrigin(raw: string, allowNonLoopback: boolean): string {
  const url = new URL(raw);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new TypeError("origin must use HTTP(S)");
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) throw new TypeError("origin must not include credentials, path, query, or fragment");
  const host = url.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (!allowNonLoopback && !isLoopbackHostname(host)) throw new TypeError("non-loopback origin requires allowNonLoopback=true");
  return url.origin;
}

function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  return host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1";
}

function ownerKind(value: unknown): "Workspace" | "Capsule" | "Resource" {
  if (value === "Workspace" || value === "Capsule" || value === "Resource") return value;
  throw new HttpError("invalid_request", "ownerRef.kind is invalid", 400);
}

function subjectKind(value: unknown): "Principal" | "ServiceAccount" | "Capsule" | "Resource" {
  if (value === "Principal" || value === "ServiceAccount" || value === "Capsule" || value === "Resource") return value;
  throw new HttpError("invalid_request", "subjectRef.kind is invalid", 400);
}

function visibility(value: unknown): "private" | "workspace" | "public" {
  if (value === "private" || value === "workspace" || value === "public") return value;
  throw new HttpError("invalid_request", "spec.access.visibility is invalid", 400);
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

function apiError(code: string, message: string, status: number): Response {
  return json({ error: code, message }, status);
}

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(value, { status, headers: { "content-type": "application/json; charset=utf-8", ...Object.fromEntries(new Headers(headers)) } });
}

function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function cors(request: Request, response: Response, allowedOrigins: ReadonlySet<string>): Response {
  const origin = request.headers.get("origin");
  if (!origin) return response;
  let allowed = allowedOrigins.has(origin);
  try {
    const parsed = new URL(origin);
    const host = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
    allowed ||= parsed.protocol === "http:" && (host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1");
  } catch { allowed = false; }
  if (!allowed) return response;
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-methods", "GET, POST, PATCH, DELETE, OPTIONS");
  headers.set("access-control-allow-headers", "authorization, content-type, if-match");
  headers.set("vary", "Origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
