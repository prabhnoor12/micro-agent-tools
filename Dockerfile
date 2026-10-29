FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    LOG_LEVEL=warn \
    NODE_OPTIONS=--max-old-space-size=512

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY index.html llms.txt llms-full.txt ./

# Public dir is what the Worker serves; keep the image layout identical.
RUN mkdir -p public && cp index.html llms.txt llms-full.txt public/

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/status || exit 1

CMD ["node", "src/api/edge_server.js"]
