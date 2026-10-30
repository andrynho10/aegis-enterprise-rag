FROM python:3.12-slim

LABEL maintainer="AegisRAG Enterprise Security Team"
LABEL description="Enterprise Agentic RAG with Entra ID/AD RBAC, ChromaDB Pre-Retrieval Filtering, Presidio PII (Ley 21.719) & Hybrid LLM Router"

WORKDIR /app

# Create non-root corporate service user (Principle of Least Privilege)
RUN groupadd -r aegis && useradd -r -g aegis aegis

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/storage && chown -R aegis:aegis /app

USER aegis
EXPOSE 8080

CMD ["python", "run_server.py", "--fastapi"]
