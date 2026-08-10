import type { DevPrincipal } from "./types.ts";

interface AuthorizationCode {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly nonce?: string;
  readonly scope: string;
  readonly principal: DevPrincipal;
  readonly expiresAt: number;
}

export interface AuthenticatedGrant {
  readonly clientId: string;
  readonly principal: DevPrincipal;
  readonly publicSubject: string;
  readonly scope: string;
  readonly expiresAt: number;
}

export interface OidcProviderOptions {
  readonly origin: string;
  readonly principal: DevPrincipal;
  readonly allowedRedirectUris?: readonly string[];
}

export class DevOidcProvider {
  readonly #origin: string;
  readonly #principal: DevPrincipal;
  readonly #allowedRedirectUris: ReadonlySet<string>;
  readonly #codes = new Map<string, AuthorizationCode>();
  readonly #accessTokens = new Map<string, AuthenticatedGrant>();
  readonly #refreshTokens = new Map<string, AuthenticatedGrant>();
  readonly #keyPair: CryptoKeyPair;
  readonly #jwk: JsonWebKey;
  readonly #kid: string;

  private constructor(options: OidcProviderOptions, keyPair: CryptoKeyPair, jwk: JsonWebKey, kid: string) {
    this.#origin = options.origin.replace(/\/+$/u, "");
    this.#principal = options.principal;
    this.#allowedRedirectUris = new Set(options.allowedRedirectUris ?? []);
    this.#keyPair = keyPair;
    this.#jwk = jwk;
    this.#kid = kid;
  }

  static async create(options: OidcProviderOptions): Promise<DevOidcProvider> {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const kid = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(jwk))))).slice(0, 16);
    return new DevOidcProvider(options, keyPair, jwk, kid);
  }

  discovery(): Record<string, unknown> {
    return {
      issuer: this.#origin,
      authorization_endpoint: `${this.#origin}/oauth/authorize`,
      token_endpoint: `${this.#origin}/oauth/token`,
      jwks_uri: `${this.#origin}/oauth/jwks`,
      userinfo_endpoint: `${this.#origin}/oauth/userinfo`,
      revocation_endpoint: `${this.#origin}/oauth/revoke`,
      introspection_endpoint: `${this.#origin}/oauth/introspect`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["pairwise"],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
      claims_parameter_supported: false,
      scopes_supported: ["openid", "profile", "email", "offline_access", "capsules:read", "capsules:write"],
      claims_supported: ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "nonce"],
    };
  }

  jwks(): Record<string, unknown> {
    return { keys: [{ ...this.#jwk, kid: this.#kid, use: "sig", alg: "ES256" }] };
  }

  async authorize(url: URL): Promise<Response> {
    const responseType = url.searchParams.get("response_type");
    const clientId = bounded(url.searchParams.get("client_id"), 256);
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = bounded(url.searchParams.get("state"), 2_048);
    const nonce = bounded(url.searchParams.get("nonce"), 2_048, true);
    const scope = bounded(url.searchParams.get("scope"), 2_048) ?? "";
    const codeChallenge = bounded(url.searchParams.get("code_challenge"), 128);
    if (responseType !== "code" || !clientId || !redirectUri || !state || !codeChallenge || !/^[A-Za-z0-9_-]{43}$/u.test(codeChallenge) || url.searchParams.get("code_challenge_method") !== "S256") {
      return oauthError("invalid_request", "authorization code + PKCE S256 is required", 400);
    }
    if (!this.#redirectAllowed(redirectUri)) {
      return oauthError("invalid_request", "redirect_uri must be an allowed loopback URI", 400);
    }
    const code = randomToken();
    this.#codes.set(code, {
      clientId,
      redirectUri: new URL(redirectUri).toString(),
      codeChallenge,
      ...(nonce ? { nonce } : {}),
      scope,
      principal: this.#principal,
      expiresAt: Date.now() + 5 * 60_000,
    });
    const destination = new URL(redirectUri);
    destination.searchParams.set("code", code);
    destination.searchParams.set("state", state);
    return Response.redirect(destination, 302);
  }

  async token(request: Request): Promise<Response> {
    const form = new URLSearchParams(await request.text());
    const grantType = form.get("grant_type");
    if (grantType === "authorization_code") return await this.#authorizationCodeGrant(form);
    if (grantType === "refresh_token") return await this.#refreshTokenGrant(form);
    return oauthError("unsupported_grant_type", "grant_type is not supported", 400);
  }

  async userinfo(request: Request): Promise<Response> {
    const grant = this.authenticate(request);
    if (!grant) return oauthError("invalid_token", "access token is invalid or expired", 401);
    return json({
      sub: grant.publicSubject,
      email: grant.principal.email,
      email_verified: true,
      name: grant.principal.name,
    }, 200, { "cache-control": "no-store" });
  }

  authenticate(request: Request): AuthenticatedGrant | null {
    const token = bearer(request);
    if (!token) return null;
    const grant = this.#accessTokens.get(token);
    if (!grant || grant.expiresAt <= Date.now()) {
      this.#accessTokens.delete(token);
      return null;
    }
    return grant;
  }

  revoke(request: Request): Promise<Response> {
    return request.text().then((body) => {
      const token = new URLSearchParams(body).get("token");
      if (token) {
        this.#accessTokens.delete(token);
        this.#refreshTokens.delete(token);
      }
      return new Response(null, { status: 200 });
    });
  }

  introspect(request: Request): Promise<Response> {
    return request.text().then((body) => {
      const token = new URLSearchParams(body).get("token") ?? "";
      const grant = this.#accessTokens.get(token) ?? this.#refreshTokens.get(token);
      if (!grant || grant.expiresAt <= Date.now()) return json({ active: false });
      return json({ active: true, client_id: grant.clientId, sub: grant.publicSubject, scope: grant.scope, exp: Math.floor(grant.expiresAt / 1_000) });
    });
  }

  async #authorizationCodeGrant(form: URLSearchParams): Promise<Response> {
    const code = form.get("code") ?? "";
    const grant = this.#codes.get(code);
    this.#codes.delete(code);
    const verifier = form.get("code_verifier") ?? "";
    const clientId = form.get("client_id") ?? "";
    const redirectUri = form.get("redirect_uri") ?? "";
    if (!grant || grant.expiresAt <= Date.now() || clientId !== grant.clientId || redirectUri !== grant.redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/u.test(verifier)) {
      return oauthError("invalid_grant", "authorization code is invalid", 400);
    }
    const actualChallenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    if (!safeEqual(actualChallenge, grant.codeChallenge)) return oauthError("invalid_grant", "PKCE verification failed", 400);
    return await this.#issueTokens(grant.clientId, grant.principal, grant.scope, grant.nonce);
  }

  async #refreshTokenGrant(form: URLSearchParams): Promise<Response> {
    const token = form.get("refresh_token") ?? "";
    const grant = this.#refreshTokens.get(token);
    this.#refreshTokens.delete(token);
    if (!grant || grant.expiresAt <= Date.now() || form.get("client_id") !== grant.clientId) {
      return oauthError("invalid_grant", "refresh token is invalid", 400);
    }
    return await this.#issueTokens(grant.clientId, grant.principal, grant.scope);
  }

  async #issueTokens(clientId: string, principal: DevPrincipal, scope: string, nonce?: string): Promise<Response> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const publicSubject = await pairwiseSubject(clientId, principal.sub);
    const accessGrant: AuthenticatedGrant = { clientId, principal, publicSubject, scope, expiresAt: Date.now() + 3_600_000 };
    const refreshGrant: AuthenticatedGrant = { ...accessGrant, expiresAt: Date.now() + 7 * 24 * 3_600_000 };
    this.#accessTokens.set(accessToken, accessGrant);
    this.#refreshTokens.set(refreshToken, refreshGrant);
    const now = Math.floor(Date.now() / 1_000);
    const idToken = await this.#signJwt({
      iss: this.#origin,
      sub: publicSubject,
      aud: clientId,
      iat: now,
      exp: now + 3_600,
      email: principal.email,
      email_verified: true,
      name: principal.name,
      ...(nonce ? { nonce } : {}),
    });
    return json({ access_token: accessToken, token_type: "Bearer", expires_in: 3_600, refresh_token: refreshToken, id_token: idToken, scope }, 200, { "cache-control": "no-store", pragma: "no-cache" });
  }

  async #signJwt(claims: Record<string, unknown>): Promise<string> {
    const header = base64Url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: this.#kid })));
    const payload = base64Url(new TextEncoder().encode(JSON.stringify(claims)));
    const signingInput = `${header}.${payload}`;
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.#keyPair.privateKey, new TextEncoder().encode(signingInput)));
    return `${signingInput}.${base64Url(ecdsaJoseSignature(signature))}`;
  }

  #redirectAllowed(raw: string): boolean {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return false;
    }
    if (url.username || url.password || url.hash) return false;
    if (this.#allowedRedirectUris.has(url.toString())) return true;
    return url.protocol === "http:" && isLoopbackHost(url.hostname);
  }
}

function bearer(request: Request): string | null {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/u.exec(request.headers.get("authorization") ?? "");
  return match?.[1] ?? null;
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function pairwiseSubject(clientId: string, subject: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${clientId}\0${subject}`)));
  return `tsub_${base64Url(digest).slice(0, 32)}`;
}

function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let index = 0; index < left.length; index += 1) result |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return result === 0;
}

function ecdsaJoseSignature(signature: Uint8Array): Uint8Array {
  if (signature.length === 64) return signature;
  if (signature[0] !== 0x30) throw new Error("unexpected ECDSA signature encoding");
  let offset = 2;
  if ((signature[1] ?? 0) > 0x80) offset += (signature[1] ?? 0) & 0x7f;
  if (signature[offset] !== 0x02) throw new Error("invalid ECDSA signature");
  const rLength = signature[offset + 1] ?? 0;
  const r = signature.slice(offset + 2, offset + 2 + rLength);
  offset += 2 + rLength;
  if (signature[offset] !== 0x02) throw new Error("invalid ECDSA signature");
  const sLength = signature[offset + 1] ?? 0;
  const s = signature.slice(offset + 2, offset + 2 + sLength);
  const output = new Uint8Array(64);
  output.set(r.slice(Math.max(0, r.length - 32)), 32 - Math.min(32, r.length));
  output.set(s.slice(Math.max(0, s.length - 32)), 64 - Math.min(32, s.length));
  return output;
}

function bounded(value: string | null, max: number, optional = false): string | null {
  if (value === null) return optional ? null : null;
  return value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value) ? value : null;
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  return normalized === "localhost" || normalized.endsWith(".localhost") || normalized === "127.0.0.1" || normalized === "::1";
}

function oauthError(error: string, description: string, status: number): Response {
  return json({ error, error_description: description }, status, { "cache-control": "no-store" });
}

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(value, { status, headers: { "content-type": "application/json; charset=utf-8", ...Object.fromEntries(new Headers(headers)) } });
}
