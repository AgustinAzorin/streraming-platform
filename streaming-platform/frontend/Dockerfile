# ---------- STAGE 1: BUILD ----------
FROM node:20-alpine AS builder

WORKDIR /workspace
RUN apk add --no-cache python3 make g++ git

COPY package.json package-lock.json ./
COPY nx.json tsconfig.base.json ./
COPY apps ./apps
COPY libs ./libs

RUN npm ci

ARG SERVICE_NAME=frontend
# Nx build para Next (genera .next en dist)
RUN npx nx build ${SERVICE_NAME} --skip-nx-cache

# ---------- STAGE 2: RUN ----------
FROM node:20-alpine AS runner

WORKDIR /app

# instalar solo deps necesarias para start
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

ARG SERVICE_NAME=frontend
COPY --from=builder /workspace/dist/apps/${SERVICE_NAME} ./dist

ENV NODE_ENV=production
EXPOSE 3000

# Next.js en Nx suele usar "node dist/main.js" si está configurado; si tu build usa next start, ajusta.
# por lo general Nx crea un servidor que corre node dist/main.js
CMD ["node", "dist/main.js"]
