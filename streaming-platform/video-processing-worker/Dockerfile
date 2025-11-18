# ---------- STAGE 1: BUILD ----------
FROM node:20-alpine AS builder

WORKDIR /workspace
RUN apk add --no-cache python3 make g++ git

COPY package.json package-lock.json ./
COPY nx.json tsconfig.base.json ./
COPY apps ./apps
COPY libs ./libs

RUN npm ci

ARG SERVICE_NAME=video-processing-worker
RUN npx nx build ${SERVICE_NAME} --skip-nx-cache

# ---------- STAGE 2: RUNTIME (ffmpeg + tools) ----------
FROM node:20-alpine AS runner

WORKDIR /app

# instalar dependencias de sistema (ffmpeg)
RUN apk add --no-cache ffmpeg bash

# copiar build
COPY --from=builder /workspace/dist/apps/video-processing-worker ./dist

# solo dependencias de prod
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

ENV NODE_ENV=production

# el worker no necesita exponer puerto
CMD ["node", "dist/main.js"]
