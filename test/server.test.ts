import { describe, expect, test } from "bun:test";
import { createDevServer, type TakosumiDevServer } from "../src/server.ts";

const origin = "http://127.0.0.1:8792";
const bootstrapHeaders = { authorization: "Bearer takosumi-dev-token", "content-type": "application/json" };
describe("discovery truth", () => {
  test("advertises OIDC and Interfaces without claiming Stack or OpenTofu authority", async () => {
    const server = await createDevServer();
    const discovery = await json(server, "/.well-known/takosumi");
    expect(discovery.product).toBe("takosumi");
    expect(discovery.features).toEqual(expect.objectContaining({ oidc: true, interfaces: true, stacks: false, opentofu_runner: false }));
    const capabilities = await json(server, "/v1/capabilities");
    expect(capabilities.adapters).toEqual({ opentofu: false });
    expect((capabilities.extensions as string[])).toContain("takosumi.dev.fixtures.v1alpha1");
  });

  test("fails unknown control routes explicitly", async () => {
    const server = await createDevServer();
    const response = await request(server, "/api/v1/backups", { headers: bootstrapHeaders });
    expect(response.status).toBe(501);
    expect(await response.json()).toEqual(expect.objectContaining({ error: "not_implemented" }));
  });
});

describe("OIDC and OAuth", () => {
  test("completes authorization code + PKCE and rotates refresh tokens", async () => {
    const server = await createDevServer();
    const verifier = "a".repeat(64);
    const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    const redirectUri = "http://127.0.0.1:8787/auth/oidc/callback";
    const authorize = new URL("/oauth/authorize", origin);
    authorize.search = new URLSearchParams({ response_type: "code", client_id: "product-local", redirect_uri: redirectUri, scope: "openid profile email offline_access capsules:read", state: "state-1", nonce: "nonce-1", code_challenge: challenge, code_challenge_method: "S256" }).toString();
    const approval = await server.fetch(new Request(authorize, { redirect: "manual" }));
    expect(approval.status).toBe(302);
    const callback = new URL(approval.headers.get("location")!);
    expect(callback.searchParams.get("state")).toBe("state-1");

    const tokensResponse = await request(server, "/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: callback.searchParams.get("code")!, client_id: "product-local", redirect_uri: redirectUri, code_verifier: verifier }),
    });
    expect(tokensResponse.status).toBe(200);
    const tokens = await tokensResponse.json() as Record<string, string>;
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    const jwks = await json(server, "/oauth/jwks") as { keys: JsonWebKey[] };
    expect(await verifyJwt(tokens.id_token!, jwks.keys[0]!)).toBe(true);
    const claims = JSON.parse(Buffer.from(tokens.id_token!.split(".")[1]!, "base64url").toString()) as Record<string, unknown>;
    expect(claims).toEqual(expect.objectContaining({ iss: origin, aud: "product-local", nonce: "nonce-1", email: "developer@local.test" }));

    const userinfoResponse = await request(server, "/oauth/userinfo", { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(userinfoResponse.status).toBe(200);
    const userinfo = await userinfoResponse.json() as Record<string, string>;
    expect(userinfo.sub).toMatch(/^tsub_/u);

    const refreshedResponse = await request(server, "/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "product-local" }),
    });
    expect(refreshedResponse.status).toBe(200);
    const refreshed = await refreshedResponse.json() as Record<string, string>;
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    const replay = await request(server, "/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "product-local" }),
    });
    expect(replay.status).toBe(400);

    const introspection = await request(server, "/oauth/introspect", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: refreshed.access_token! }) });
    expect(await introspection.json()).toEqual(expect.objectContaining({ active: true, client_id: "product-local" }));
    expect((await request(server, "/oauth/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: refreshed.access_token! }) })).status).toBe(200);
    expect((await request(server, "/oauth/userinfo", { headers: { authorization: `Bearer ${refreshed.access_token}` } })).status).toBe(401);
  });

  test("rejects non-loopback redirects unless exactly allowed", async () => {
    const server = await createDevServer();
    const url = new URL("/oauth/authorize", origin);
    url.search = new URLSearchParams({ response_type: "code", client_id: "client", redirect_uri: "https://attacker.example/callback", state: "state", code_challenge: "c".repeat(43), code_challenge_method: "S256" }).toString();
    expect((await server.fetch(new Request(url))).status).toBe(400);
  });

  test("accepts RFC 6761 localhost subdomains used by product shells", async () => {
    const server = await createDevServer();
    const url = new URL("/oauth/authorize", origin);
    url.search = new URLSearchParams({ response_type: "code", client_id: "takos-local", redirect_uri: "http://admin.localhost:8787/auth/oidc/callback", state: "state", code_challenge: "c".repeat(43), code_challenge_method: "S256" }).toString();
    expect((await server.fetch(new Request(url, { redirect: "manual" }))).status).toBe(302);
  });
});

describe("product-neutral fixture control", () => {
  test("creates a Workspace, Source and Capsule and simulates plan/apply", async () => {
    const server = await createDevServer();
    const workspaceResponse = await request(server, "/api/v1/workspaces", { method: "POST", headers: bootstrapHeaders, body: JSON.stringify({ handle: "sample-product", displayName: "Sample Product" }) });
    expect(workspaceResponse.status).toBe(201);
    const workspaceId = ((await workspaceResponse.json()) as { workspace: { id: string } }).workspace.id;
    const sourceResponse = await request(server, "/api/v1/sources", { method: "POST", headers: bootstrapHeaders, body: JSON.stringify({ workspaceId, name: "sample-source", url: "https://example.test/sample.git", defaultRef: "main", defaultPath: "." }) });
    const sourceId = ((await sourceResponse.json()) as { source: { id: string } }).source.id;
    const capsuleResponse = await request(server, `/api/v1/workspaces/${workspaceId}/capsules`, { method: "POST", headers: bootstrapHeaders, body: JSON.stringify({ name: "sample", sourceId, environment: "dev", installConfigId: "default" }) });
    expect(capsuleResponse.status).toBe(201);
    const capsule = ((await capsuleResponse.json()) as { capsule: { id: string; status: string } }).capsule;
    expect(capsule.status).toBe("pending");
    const planResponse = await request(server, `/api/v1/capsules/${capsule.id}/plan`, { method: "POST", headers: bootstrapHeaders, body: "{}" });
    const runId = ((await planResponse.json()) as { run: { id: string } }).run.id;
    expect((await request(server, `/api/v1/runs/${runId}/apply`, { method: "POST", headers: bootstrapHeaders, body: "{}" })).status).toBe(200);
    const active = await json(server, `/api/v1/capsules/${capsule.id}`, { headers: bootstrapHeaders });
    expect((active.capsule as { status: string }).status).toBe("active");
  });

  test("creates and authorizes a canonical Interface for an OAuth principal", async () => {
    const server = await createDevServer();
    const session = await oauthSession(server, "interface-product");
    const interfaceResponse = await request(server, "/v1/interfaces", { method: "POST", headers: bootstrapHeaders, body: JSON.stringify({ workspaceId: "ws_local", name: "sample.api", ownerRef: { kind: "Workspace", id: "ws_local" }, spec: { type: "http.api", version: "v1", document: { baseUrl: "https://api.local.test" }, access: { visibility: "workspace" } }, resourceUri: "https://api.local.test" }) });
    expect(interfaceResponse.status).toBe(201);
    const iface = await interfaceResponse.json() as { metadata: { id: string } };
    const bindingResponse = await request(server, `/v1/interfaces/${iface.metadata.id}/bindings`, { method: "POST", headers: bootstrapHeaders, body: JSON.stringify({ subjectRef: { kind: "Principal", id: session.subject }, permissions: ["invoke"], delivery: { type: "oauth2" } }) });
    expect(bindingResponse.status).toBe(201);
    const listResponse = await request(server, `/v1/interfaces?workspaceId=ws_local&type=http.api&phase=Resolved&permission=invoke`, { headers: { authorization: `Bearer ${session.accessToken}` } });
    expect(((await listResponse.json()) as { interfaces: unknown[] }).interfaces).toHaveLength(1);
    const tokenResponse = await request(server, `/v1/interfaces/${iface.metadata.id}/token`, { method: "POST", headers: { authorization: `Bearer ${session.accessToken}`, "content-type": "application/json" }, body: JSON.stringify({ permission: "invoke" }) });
    expect(tokenResponse.status).toBe(200);
    expect(await tokenResponse.json()).toEqual(expect.objectContaining({ token_type: "Bearer", expires_in: 60, scope: "invoke", resource: "https://api.local.test" }));
  });

  test("rejects a non-loopback server origin by default", async () => {
    expect(createDevServer({ origin: "http://0.0.0.0:8792" })).rejects.toThrow("allowNonLoopback");
  });

  test("requires a strong explicit bootstrap token for non-loopback exposure", async () => {
    expect(createDevServer({ origin: "http://0.0.0.0:8792", allowNonLoopback: true })).rejects.toThrow("at least 32");
    expect((await createDevServer({ origin: "http://0.0.0.0:8792", allowNonLoopback: true, bootstrapToken: "x".repeat(32) })).origin).toBe("http://0.0.0.0:8792");
  });
});

async function oauthSession(server: TakosumiDevServer, clientId: string): Promise<{ accessToken: string; subject: string }> {
  const verifier = "b".repeat(64);
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const redirectUri = "http://localhost:3000/callback";
  const authorize = new URL("/oauth/authorize", origin);
  authorize.search = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope: "openid profile", state: "state", code_challenge: challenge, code_challenge_method: "S256" }).toString();
  const approval = await server.fetch(new Request(authorize, { redirect: "manual" }));
  const code = new URL(approval.headers.get("location")!).searchParams.get("code")!;
  const tokenResponse = await request(server, "/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: clientId, redirect_uri: redirectUri, code_verifier: verifier }) });
  const tokens = await tokenResponse.json() as Record<string, string>;
  const userinfo = await json(server, "/oauth/userinfo", { headers: { authorization: `Bearer ${tokens.access_token}` } });
  return { accessToken: tokens.access_token!, subject: userinfo.sub as string };
}

function request(server: TakosumiDevServer, path: string, init?: RequestInit): Promise<Response> {
  return server.fetch(new Request(new URL(path, origin), init));
}

async function json(server: TakosumiDevServer, path: string, init?: RequestInit): Promise<Record<string, unknown>> {
  const response = await request(server, path, init);
  expect(response.status).toBe(200);
  return await response.json() as Record<string, unknown>;
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function verifyJwt(token: string, jwk: JsonWebKey): Promise<boolean> {
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) return false;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    Buffer.from(signature, "base64url"),
    new TextEncoder().encode(`${header}.${payload}`),
  );
}
