# ---------- STAGE 1: BUILD ----------
FROM node:20-alpine AS builder

WORKDIR /workspace

# dependencias del sistema necesarias
RUN apk add --no-cache python3 make g++ git

# copy solo archivos de package para cachear npm install
COPY package.json package-lock.json ./
# Nx files necesarios para build
COPY nx.json tsconfig.base.json ./
# copy codigo (apps + libs)
COPY apps ./apps
COPY libs ./libs

# instalar dependencias (producción + dev para build)
RUN npm ci

# argumento para indicar qué servicio construir
ARG SERVICE_NAME
RUN npx nx build ${SERVICE_NAME} --skip-nx-cache

# ---------- STAGE 2: RUNTIME ----------
FROM node:20-alpine AS runner

WORKDIR /app

# instalar solo deps de producción
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# copiar el build del servicio
ARG SERVICE_NAME
COPY --from=builder /workspace/dist/apps/${SERVICE_NAME} ./dist

# variables/puerto por defecto
ARG PORT=3000
ENV PORT=${PORT}
EXPOSE ${PORT}

# set NODE_ENV para optimizaciones
ENV NODE_ENV=production

# comando por defecto
CMD ["node", "dist/main.js"]
