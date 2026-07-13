.PHONY: dev-backend dev-frontend dev install-backend install-frontend \
        docker-up docker-down docker-logs clean help

# ── Local development ──────────────────────────────────────────────────────────
install-backend:
	cd backend && python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt

install-frontend:
	cd frontend && npm install

install: install-backend install-frontend

dev-backend:
	cd backend && . venv/bin/activate && uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

dev-frontend:
	cd frontend && npm run dev

# Run both in parallel (requires 'make -j2 dev' or use two terminals)
dev:
	@echo "Run in two separate terminals:"
	@echo "  make dev-backend"
	@echo "  make dev-frontend"

# ── Production (Docker) ────────────────────────────────────────────────────────
docker-up:
	@if [ ! -f backend/.env ]; then cp backend/.env.example backend/.env && echo "Created backend/.env from example"; fi
	docker compose up --build -d
	@echo "App running at http://localhost:3000"

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-clean:
	docker compose down -v --rmi local

# ── Misc ───────────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf frontend/dist frontend/node_modules backend/venv backend/app/data/arena.db

help:
	@echo ""
	@echo "Threat Hunter Arena"
	@echo ""
	@echo "  make install          Install all dependencies"
	@echo "  make dev-backend      Start FastAPI dev server (port 8000)"
	@echo "  make dev-frontend     Start Vite dev server  (port 5173)"
	@echo ""
	@echo "  make docker-up        Build and run full stack via Docker"
	@echo "  make docker-down      Stop Docker stack"
	@echo "  make docker-logs      Tail Docker logs"
	@echo "  make docker-clean     Remove containers, volumes, images"
	@echo ""
