const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function loginPage(o: { clientName?: string; redirect?: string; req?: string; error?: string }): string {
  let host = "";
  try { host = o.redirect ? new URL(o.redirect).host : ""; } catch { /* ignore */ }
  const form = o.req
    ? `<form method="post" action="/login">
  <input type="hidden" name="req" value="${esc(o.req)}">
  <label>Password <input type="password" name="password" autofocus autocomplete="current-password" required></label>
  <button type="submit">Allow</button>
</form>`
    : "";
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-gate</title>
<style>body{font:16px system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#222}
input{font:inherit;padding:.4rem;width:100%;box-sizing:border-box;margin:.3rem 0 1rem}
button{font:inherit;padding:.5rem 1.2rem}.err{color:#b00020}.muted{color:#666}</style>
<h1>mcp-gate</h1>
${o.error ? `<p class="err">${esc(o.error)}</p>` : ""}
${o.clientName ? `<p><b>${esc(o.clientName)}</b>${host ? ` <span class="muted">(${esc(host)})</span>` : ""} wants access to your MCP servers.</p>` : ""}
${form}`;
}
