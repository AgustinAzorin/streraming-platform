# ----------------------------------------------------------
# 1) BUILD STAGE
# ----------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY nx.json ./
COPY tsconfig.base.json ./

COPY apps ./apps
COPY libs ./libs

RUN npm install

ARG SERVICE_NAME=video-processing-worker
RUN npx nx build $SERVICE_NAME

# ----------------------------------------------------------
# 2) RUNTIME STAGE (con ffmpeg)
# ----------------------------------------------------------
FROM node:20-alpine AS runner

WORKDIR /app

# Install ffmpeg
RUN apk add --no-cache ffmpeg

# Copy compiled worker
COPY --from=builder /app/dist/apps/video-processing-worker ./dist

COPY package*.json ./
RUN npm install --omit=dev

# No expose (no HTTP)
CMD ["node", "dist/main.js"]
