import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { timingSafeEqual } from "node:crypto";
import type { Config } from "./config.js";
import { Tokens } from "./tokens.js";
import { loginPage } from "./loginPage.js";

const AUTHREQ_TTL = 10 * 60;
const CODE_TTL = 5 * 60;
const CLIENT_TTL = 10 * 365 * 24 * 3600;

/**
 * Stateless single-user OAuth 2.1 provider.
 *
 * - Dynamic client registration: the client id *is* a signed JWT carrying the
 *   registered metadata, so restarts lose nothing. All clients are treated as
 *   public clients (PKCE is mandatory anyway); no client secret is issued.
 * - Authorization: renders a password page; the pending request travels in a
 *   signed `authreq` JWT in the form. A correct password yields a `code` JWT.
 * - Tokens: `access` (short) and `refresh` (long) JWTs. Codes are single-use
 *   while the process lives (best effort — they also expire in 5 minutes).
 */
export class GateProvider implements OAuthServerProvider {
  readonly tokens: Tokens;
  private usedCodes = new Set<string>();
  private failures = new Map<string, { count: number; until: number }>();

  constructor(private config: Config) {
    this.tokens = new Tokens(config.signingKey, config.issuer.href);
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: async (clientId) => {
        const p = await this.tokens.verify("client", clientId);
        if (!p) return undefined;
        return { ...(p.client as object), client_id: clientId } as OAuthClientInformationFull;
      },
      registerClient: async (client) => {
        const { client_secret: _s, client_secret_expires_at: _e, ...meta } = client as OAuthClientInformationFull;
        const info = { ...meta, token_endpoint_auth_method: "none", client_id_issued_at: Math.floor(Date.now() / 1000) };
        const client_id = await this.tokens.sign("client", { client: info }, CLIENT_TTL);
        return { ...info, client_id } as OAuthClientInformationFull;
      },
    };
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const req = await this.tokens.sign(
      "authreq",
      {
        cid: client.client_id,
        redirect: params.redirectUri,
        challenge: params.codeChallenge,
        state: params.state,
        scopes: params.scopes ?? [],
        resource: params.resource?.href,
      },
      AUTHREQ_TTL,
    );
    res.status(200).type("html").send(loginPage({ clientName: client.client_name ?? "an MCP client", redirect: params.redirectUri, req }));
  }

  /** POST /login: password + signed request → redirect with code. */
  async login(ip: string, password: string, req: string, res: Response): Promise<void> {
    const p = await this.tokens.verify("authreq", req);
    if (!p) {
      res.status(400).type("html").send(loginPage({ error: "This login link expired. Start again from your MCP client." }));
      return;
    }
    const lock = this.failures.get(ip);
    if (lock && lock.count >= 5 && lock.until > Date.now()) {
      res.status(429).type("html").send(loginPage({ error: "Too many attempts. Try again in 15 minutes." }));
      return;
    }
    if (!this.passwordMatches(password)) {
      const f = this.failures.get(ip) ?? { count: 0, until: 0 };
      f.count += 1;
      f.until = Date.now() + 15 * 60 * 1000;
      this.failures.set(ip, f);
      res.status(401).type("html").send(loginPage({ error: "Wrong password.", req, redirect: p.redirect as string }));
      return;
    }
    this.failures.delete(ip);
    const code = await this.tokens.sign(
      "code",
      { cid: p.cid, redirect: p.redirect, challenge: p.challenge, scopes: p.scopes, resource: p.resource },
      CODE_TTL,
    );
    const url = new URL(p.redirect as string);
    url.searchParams.set("code", code);
    if (p.state) url.searchParams.set("state", p.state as string);
    res.redirect(302, url.href);
  }

  private passwordMatches(given: string): boolean {
    const a = Buffer.from(given);
    const b = Buffer.from(this.config.password);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    const p = await this.tokens.verify("code", code);
    if (!p || p.cid !== client.client_id) throw new InvalidGrantError("Invalid or expired authorization code");
    return p.challenge as string;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
    _codeVerifier?: string,
    redirectUri?: string,
    _resource?: URL,
  ): Promise<OAuthTokens> {
    const p = await this.tokens.verify("code", code);
    if (!p || p.cid !== client.client_id) throw new InvalidGrantError("Invalid or expired authorization code");
    if (this.usedCodes.has(p.jti!)) throw new InvalidGrantError("Authorization code already used");
    if (redirectUri && redirectUri !== p.redirect) throw new InvalidGrantError("redirect_uri mismatch");
    this.usedCodes.add(p.jti!);
    return this.issueTokens(client.client_id, (p.scopes as string[]) ?? []);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
    const p = await this.tokens.verify("refresh", refreshToken);
    if (!p || p.cid !== client.client_id) throw new InvalidGrantError("Invalid or expired refresh token");
    return this.issueTokens(client.client_id, scopes ?? ((p.scopes as string[]) ?? []));
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const p = await this.tokens.verify("access", token);
    if (!p) throw new InvalidTokenError("Invalid or expired access token");
    return { token, clientId: p.cid as string, scopes: (p.scopes as string[]) ?? [], expiresAt: p.exp };
  }

  private async issueTokens(cid: string, scopes: string[]): Promise<OAuthTokens> {
    const [access_token, refresh_token] = await Promise.all([
      this.tokens.sign("access", { cid, scopes }, this.config.accessTokenTtlSec),
      this.tokens.sign("refresh", { cid, scopes }, this.config.refreshTokenTtlSec),
    ]);
    return { access_token, token_type: "bearer", expires_in: this.config.accessTokenTtlSec, refresh_token, scope: scopes.join(" ") || undefined };
  }
}
