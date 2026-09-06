import http from "node:http";
import https from "node:https";
import type { Request, Response } from "express";
import type { Upstream } from "./config.js";

const HOP = new Set(["host", "authorization", "connection", "keep-alive", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);

/** Streams a request to the upstream MCP endpoint with the upstream's own bearer token. */
export function proxyTo(upstream: Upstream) {
  const target = new URL(upstream.url);
  const client = target.protocol === "https:" ? https : http;
  return (req: Request, res: Response): void => {
    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined && !HOP.has(k)) headers[k] = v;
    headers.host = target.host;
    if (upstream.token) headers.authorization = `Bearer ${upstream.token}`;
    const up = client.request(
      { protocol: target.protocol, hostname: target.hostname, port: target.port || undefined, path: target.pathname + target.search, method: req.method, headers },
      (ur) => {
        res.status(ur.statusCode ?? 502);
        for (const [k, v] of Object.entries(ur.headers)) if (v !== undefined && k !== "transfer-encoding") res.setHeader(k, v);
        ur.pipe(res);
      },
    );
    up.on("error", (err) => {
      if (!res.headersSent) res.status(502).json({ jsonrpc: "2.0", error: { code: -32000, message: `upstream ${upstream.name}: ${err.message}` }, id: null });
      else res.end();
    });
    res.on("close", () => up.destroy());
    req.pipe(up);
  };
}
