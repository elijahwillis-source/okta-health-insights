FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY package.json server.js google.js policy.js ./
COPY public ./public
# shared policy (known-error rules, app decisions, audit log) lives here: mount a persistent volume at /app/data
RUN mkdir -p /app/data && chown node:node /app/data
ENV DATA_DIR=/app/data
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["node", "server.js"]
