FROM oven/bun:1-slim
LABEL org.opencontainers.image.source=https://github.com/baileywickham/mcp-gate
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY src ./src
ENV PORT=8080
EXPOSE 8080
USER bun
CMD ["bun", "src/index.ts"]
