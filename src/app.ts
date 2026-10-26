import express from "express";
import { mcpAuthRouter, mcpAuthMetadataRouter, createOAuthMetadata, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { timingSafeEqual } from "node:crypto";
import type { Config } from "./config.js";
import { GateProvider } from "./provider.js";
import { proxyTo } from "./proxy.js";

/** A service token is a shared secret, so compare in constant time and only against equal lengths. */
function isServiceToken(config: Config, token: string): boolean {
  const given = Buffer.from(token);
  return config.serviceTokens.some((t) => {
    const want = Buffer.from(t);
    return want.length === given.length && timingSafeEqual(want, given);
  });
}

export function createApp(config: Config) {
  const provider = new GateProvider(config);
  // Verifier used on the proxied routes: a configured service token authenticates
  // directly; anything else goes through the OAuth provider as before.
  const verifier = {
    verifyAccessToken: async (token: string) =>
      isServiceToken(config, token)
        ? // The SDK requires an expiry; a service token is checked against the secret on
          // every request, so hand it a rolling one that is always in the future.
          { token, clientId: "service", scopes: [], expiresAt: Math.floor(Date.now() / 1000) + 300 }
        : provider.verifyAccessToken(token),
  };
  const app = express();
  app.set("trust proxy", true);
  app.disable("x-powered-by");
  // No client compresses request bodies, and the body parsers would otherwise inflate
  // gzip/deflate/br for anyone before auth (CVE-2026-111497 was in the brotli decoder).
  app.use((req, res, next) => {
    const enc = req.headers["content-encoding"];
    if (enc && enc.toLowerCase() !== "identity") return void res.status(415).type("text").send("compressed request bodies are not accepted\n");
    next();
  });

  const resourceUrl = (name: string) => new URL(`/${name}/mcp`, config.issuer);
  const [first, ...others] = config.upstreams;

  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: config.issuer,
      resourceServerUrl: first ? resourceUrl(first.name) : undefined,
      resourceName: first?.name,
      clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
    }),
  );
  const oauthMetadata = createOAuthMetadata({ provider, issuerUrl: config.issuer });
  for (const u of others) app.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl: resourceUrl(u.name), resourceName: u.name }));

  app.post("/login", express.urlencoded({ extended: false }), (req, res) => {
    const { password, req: authreq } = req.body as { password?: string; req?: string };
    void provider.login(req.ip ?? "?", password ?? "", authreq ?? "", res);
  });

  app.get("/healthz", (_req, res) => void res.type("text").send("ok"));
  app.get("/", (_req, res) => void res.type("text").send(`mcp-gate: ${config.upstreams.map((u) => `/${u.name}/mcp`).join(" ") || "(no upstreams)"}\n`));

  for (const u of config.upstreams) {
    app.all(
      `/${u.name}/mcp`,
      requireBearerAuth({ verifier, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl(u.name)) }),
      proxyTo(u),
    );
  }
  return app;
}
