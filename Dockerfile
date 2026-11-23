FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY package.json server.js google.js osctrl.js policy.js auth.js audit.js geo.js slack.js alerts.js ./
COPY public ./public
# the internal CA that signs *.coolify.thoughtspot.com, needed to trust osctrl's HTTPS endpoint (see sightline-osctrl-integration.md).
# Harmless when osctrl is not configured; never disable certificate verification instead of trusting this.
COPY thoughtspot-vmp01-ca.pem ./
ENV NODE_EXTRA_CA_CERTS=/app/thoughtspot-vmp01-ca.pem
# shared policy (known-error rules, app decisions, audit log) lives here: mount a persistent volume at /app/data
RUN mkdir -p /app/data && chown node:node /app/data
ENV DATA_DIR=/app/data
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["node", "server.js"]
