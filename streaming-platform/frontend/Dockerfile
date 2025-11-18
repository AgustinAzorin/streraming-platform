# ----------------------------------------------------------
# 1) BUILD stage
# ----------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY nx.json ./
COPY tsconfig.base.json ./

COPY apps ./apps
COPY libs ./libs

RUN npm install

ARG SERVICE_NAME=frontend
RUN npx nx build $SERVICE_NAME

# ----------------------------------------------------------
# 2) RUN stage (serve static export)
# ----------------------------------------------------------
FROM node:20-alpine AS runner

WORKDIR /app

# Copy compiled Next.js output
COPY --from=builder /app/dist/apps/frontend ./dist

# Static export serve
RUN npm install -g serve

EXPOSE 3000

CMD ["serve", "-s", "dist"]
