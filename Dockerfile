# Stage 1: Build
FROM python:3.11-slim as build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim
WORKDIR /app
COPY --from=build /app /app
COPY ./app ./app
RUN useradd -m nonroot
USER nonroot
CMD ["python", "app/app.py"]