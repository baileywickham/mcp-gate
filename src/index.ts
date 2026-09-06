import { loadConfig } from "./config.js";
import { createApp } from "./app.js";

const config = loadConfig();
const app = createApp(config);
app.listen(config.port, () => {
  console.log(`mcp-gate ${config.issuer.href} on :${config.port}; upstreams: ${config.upstreams.map((u) => u.name).join(", ") || "none"}`);
});
