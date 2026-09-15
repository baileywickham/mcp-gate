import { test, expect, beforeAll, afterAll } from "bun:test";
import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app.js";
import type { Config } from "../src/config.js";

let upstream: http.Server, gate: http.Server, base: string;
const seen: { auth?: string; body?: string; path?: string }[] = [];

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ auth: req.headers.authorization, body, path: req.url });
      if (req.headers.accept?.includes("text/event-stream")) {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n");
        res.end();
      } else res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ echoed: body }));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const upPort = (upstream.address() as AddressInfo).port;
  gate = http.createServer();
  await new Promise<void>((r) => gate.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(gate.address() as AddressInfo).port}`;
  const config: Config = {
    issuer: new URL(base),
    port: 0,
    password: "correct-horse-battery",
    signingKey: new TextEncoder().encode("0123456789abcdef0123456789abcdef"),
    upstreams: [
      { name: "apple", url: `http://127.0.0.1:${upPort}/mcp`, token: "upstream-secret" },
      { name: "other", url: `http://127.0.0.1:${upPort}/other` },
    ],
    accessTokenTtlSec: 60,
    refreshTokenTtlSec: 120,
    serviceTokens: ["service-token-for-tests-0123456789ab"],
  };
  gate.on("request", createApp(config));
});
afterAll(() => { gate.close(); upstream.close(); });

const b64url = (b: Buffer) => b.toString("base64url");
const form = (o: Record<string, string>) => new URLSearchParams(o).toString();

test("full OAuth 2.1 flow: discovery, DCR, login, PKCE, proxy, refresh", async () => {
  // 1. unauthenticated → 401 with resource metadata pointer
  const r401 = await fetch(`${base}/apple/mcp`, { method: "POST", body: "{}" });
  expect(r401.status).toBe(401);
  expect(r401.headers.get("www-authenticate")).toContain("/.well-known/oauth-protected-resource/apple/mcp");

  // 2. discovery
  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/apple/mcp`)).json();
  expect(prm.resource).toBe(`${base}/apple/mcp`);
  expect(prm.authorization_servers).toEqual([`${base}/`]);
  const prm2 = await (await fetch(`${base}/.well-known/oauth-protected-resource/other/mcp`)).json();
  expect(prm2.resource).toBe(`${base}/other/mcp`);
  const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  expect(as.code_challenge_methods_supported).toEqual(["S256"]);
  expect(as.registration_endpoint).toBe(`${base}/register`);

  // 3. dynamic client registration → stateless client id, public client
  const reg = await fetch(as.registration_endpoint, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Claude", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }),
  });
  expect(reg.status).toBe(201);
  const client = await reg.json();
  expect(client.client_secret).toBeUndefined();
  expect(client.token_endpoint_auth_method).toBe("none");
  expect(client.client_id.split(".").length).toBe(3);

  // 4. authorize → login page
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const authz = new URL(as.authorization_endpoint);
  authz.search = form({ response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uris[0], code_challenge: challenge, code_challenge_method: "S256", state: "xyz", resource: `${base}/apple/mcp` });
  const page = await fetch(authz);
  expect(page.status).toBe(200);
  const html = await page.text();
  expect(html).toContain("Claude");
  const req = /name="req" value="([^"]+)"/.exec(html)![1];

  // 5. wrong password → 401, right password → 302 with code + state
  const bad = await fetch(`${base}/login`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form({ req, password: "nope" }), redirect: "manual" });
  expect(bad.status).toBe(401);
  const good = await fetch(`${base}/login`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form({ req, password: "correct-horse-battery" }), redirect: "manual" });
  expect(good.status).toBe(302);
  const loc = new URL(good.headers.get("location")!);
  expect(loc.origin + loc.pathname).toBe("https://claude.ai/api/mcp/auth_callback");
  expect(loc.searchParams.get("state")).toBe("xyz");
  const code = loc.searchParams.get("code")!;

  // 6. token: bad verifier rejected, good verifier issues tokens, code is single-use
  const tokenReq = (body: Record<string, string>) => fetch(as.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form(body) });
  const badPkce = await tokenReq({ grant_type: "authorization_code", code, client_id: client.client_id, code_verifier: "wrong", redirect_uri: client.redirect_uris[0] });
  expect(badPkce.status).toBe(400);
  const tok = await tokenReq({ grant_type: "authorization_code", code, client_id: client.client_id, code_verifier: verifier, redirect_uri: client.redirect_uris[0] });
  expect(tok.status).toBe(200);
  const tokens = await tok.json();
  expect(tokens.token_type).toBe("bearer");
  expect(tokens.refresh_token).toBeTruthy();
  const replay = await tokenReq({ grant_type: "authorization_code", code, client_id: client.client_id, code_verifier: verifier, redirect_uri: client.redirect_uris[0] });
  expect(replay.status).toBe(400);

  // 7. proxied call carries the upstream's own token, streams SSE back
  const call = await fetch(`${base}/apple/mcp`, { method: "POST", headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
  expect(call.status).toBe(200);
  expect(call.headers.get("content-type")).toContain("text/event-stream");
  expect(await call.text()).toContain('"ok":true');
  expect(seen.at(-1)).toMatchObject({ auth: "Bearer upstream-secret", path: "/mcp", body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
  const other = await fetch(`${base}/other/mcp`, { method: "POST", headers: { authorization: `Bearer ${tokens.access_token}` }, body: "x" });
  expect(other.status).toBe(200);
  expect(seen.at(-1)).toMatchObject({ auth: undefined, path: "/other" });

  // 8. garbage / wrong-type token rejected
  expect((await fetch(`${base}/apple/mcp`, { method: "POST", headers: { authorization: `Bearer ${tokens.refresh_token}` }, body: "{}" })).status).toBe(401);
  expect((await fetch(`${base}/apple/mcp`, { method: "POST", headers: { authorization: `Bearer ${client.client_id}` }, body: "{}" })).status).toBe(401);

  // 9. refresh
  const ref = await tokenReq({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id });
  expect(ref.status).toBe(200);
  const fresh = await ref.json();
  expect(fresh.access_token).not.toBe(tokens.access_token);
  expect((await fetch(`${base}/apple/mcp`, { method: "POST", headers: { authorization: `Bearer ${fresh.access_token}` }, body: "{}" })).status).toBe(200);
});

test("login with an expired/forged request is refused", async () => {
  const r = await fetch(`${base}/login`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form({ req: "not.a.jwt", password: "correct-horse-battery" }) });
  expect(r.status).toBe(400);
});

test("healthz and index", async () => {
  expect(await (await fetch(`${base}/healthz`)).text()).toBe("ok");
  expect(await (await fetch(`${base}/`)).text()).toContain("/apple/mcp");
});

test("a configured service token authenticates without OAuth, a wrong one does not", async () => {
  const ok = await fetch(`${base}/apple/mcp`, {
    method: "POST",
    headers: { authorization: "Bearer service-token-for-tests-0123456789ab", "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  expect(ok.status).toBe(200);
  expect(seen.at(-1)?.auth).toBe("Bearer upstream-secret");  // upstream token swapped in, service token never forwarded

  const bad = await fetch(`${base}/apple/mcp`, {
    method: "POST",
    headers: { authorization: "Bearer service-token-for-tests-0123456789XX" },
    body: "{}",
  });
  expect(bad.status).toBe(401);
});
