# The Better IAM documentation site (apps/docs), built from the repository root: the site imports the
# workspace packages and type-checks its code samples against their build output, so the whole
# workspace is installed and built first. Railway uses this through /railway.json.
#
#   docker build -f apps/docs/Dockerfile -t better-iam-docs .
#   docker run -p 3000:3000 better-iam-docs
FROM node:24-bookworm-slim

ENV CI=1 NEXT_TELEMETRY_DISABLED=1
RUN npm install -g pnpm@11.19.0

WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm build

# Baked into the static pages at build time. Railway passes service variables and its own
# RAILWAY_PUBLIC_DOMAIN as build arguments; DOCS_SITE_URL wins when set (a custom domain).
ARG DOCS_SITE_URL
ARG RAILWAY_PUBLIC_DOMAIN
ARG NEXT_PUBLIC_DOCS_REPOSITORY_URL=https://github.com/Better-IAM/better-iam
ARG NEXT_PUBLIC_DOCS_REPOSITORY_BRANCH=main
# Optional: the site's X account on link cards, and search console ownership tokens.
ARG DOCS_X_HANDLE
ARG DOCS_GOOGLE_SITE_VERIFICATION
ARG DOCS_BING_SITE_VERIFICATION
ARG DOCS_YANDEX_VERIFICATION
RUN pnpm --filter @better-iam/docs build

ENV NODE_ENV=production
WORKDIR /app/apps/docs
# `next start` listens on $PORT, which Railway injects (3000 when unset).
CMD ["node", "node_modules/next/dist/bin/next", "start", "--hostname", "0.0.0.0"]
