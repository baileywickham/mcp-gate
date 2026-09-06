import express from "express";
import { mcpAuthRouter, mcpAuthMetadataRouter, createOAuthMetadata, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { Config } from "./config.js";
import { GateProvider } from "./provider.js";
import { proxyTo } from "./proxy.js";

export function createApp(config: Config) {
  const provider = new GateProvider(config);
  const app = express();
  app.set("trust proxy", true);
  app.disable("x-powered-by");

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
      requireBearerAuth({ verifier: provider, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl(u.name)) }),
      proxyTo(u),
    );
  }
  return app;
}
