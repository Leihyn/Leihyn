FROM node:22-alpine AS web-build

WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig*.json vite.config.ts ./
COPY src ./src
RUN npm run build

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CASEWORKER_STATIC_DIR=/app/static \
    PORT=8080

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
RUN pip install --no-cache-dir .
COPY --from=web-build /workspace/dist ./static

EXPOSE 8080
CMD ["sh", "-c", "uvicorn app.api:api --host 0.0.0.0 --port ${PORT}"]
