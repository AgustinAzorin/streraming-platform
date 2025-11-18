# ----------------------------------------------------------
# 1) BUILD STAGE
# ----------------------------------------------------------
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Copy root package files
COPY package*.json ./
COPY nx.json ./
COPY tsconfig.base.json ./

# Copy workspace libs and app source
COPY apps ./apps
COPY libs ./libs

# Install dependencies
RUN npm install

# Build the specific service
ARG SERVICE_NAME
RUN npx nx build $SERVICE_NAME

# ----------------------------------------------------------
# 2) PRODUCTION STAGE
# ----------------------------------------------------------
FROM node:20-alpine AS runner

WORKDIR /app

# Copy from builder the dist output
ARG SERVICE_NAME
COPY --from=builder /app/dist/apps/${SERVICE_NAME} ./dist

# Install only production deps
COPY package*.json ./
RUN npm install --omit=dev

# Expose Nest port (each microservice usa su propio puerto)
ARG PORT=3006
ENV PORT=${PORT}
EXPOSE ${PORT}

# Run service
CMD ["node", "dist/main.js"]
