/** All configuration comes from the environment (set via a k8s Secret). */
export interface Upstream {
  /** Path prefix under which this MCP is exposed: https://<issuer>/<name>/mcp */
  name: string;
  /** Upstream MCP endpoint, e.g. http://192.168.0.50:8000/mcp */
  url: string;
  /** Bearer token the upstream expects (never leaves the cluster). */
  token?: string;
}

export interface Config {
  issuer: URL;
  port: number;
  password: string;
  signingKey: Uint8Array;
  upstreams: Upstream[];
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
}

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const issuer = new URL(env.MCP_GATE_ISSUER ?? required("MCP_GATE_ISSUER"));
  const key = env.MCP_GATE_SIGNING_KEY ?? required("MCP_GATE_SIGNING_KEY");
  if (key.length < 32) throw new Error("MCP_GATE_SIGNING_KEY must be at least 32 characters");
  const password = env.MCP_GATE_PASSWORD ?? required("MCP_GATE_PASSWORD");
  if (password.length < 12) throw new Error("MCP_GATE_PASSWORD must be at least 12 characters");
  let upstreams: Upstream[] = [];
  if (env.MCP_GATE_UPSTREAMS) {
    const parsed = JSON.parse(env.MCP_GATE_UPSTREAMS) as Record<string, { url: string; token?: string }>;
    upstreams = Object.entries(parsed).map(([name, u]) => ({ name, url: u.url, token: u.token }));
  }
  for (const u of upstreams) {
    if (!/^[a-z0-9-]+$/.test(u.name)) throw new Error(`upstream name "${u.name}" must be [a-z0-9-]`);
    new URL(u.url);
  }
  return {
    issuer,
    port: Number(env.PORT ?? 8080),
    password,
    signingKey: new TextEncoder().encode(key),
    upstreams,
    accessTokenTtlSec: Number(env.MCP_GATE_ACCESS_TTL ?? 3600),
    refreshTokenTtlSec: Number(env.MCP_GATE_REFRESH_TTL ?? 30 * 24 * 3600),
  };
}
