.PHONY: up down logs evaluate test test-backend test-frontend reset

up:            ## build and start the whole stack
	@test -f .env || cp .env.example .env
	docker compose up -d --build
	@echo "Dashboard: http://localhost:3000   API: http://localhost:8000/docs"

down:
	docker compose down

reset:         ## wipe the database volume
	docker compose down -v

logs:
	docker compose logs -f backend

evaluate:      ## precision/recall/F1 vs. ground truth, source-mode demo project (3 repeated runs)
	docker compose exec backend python /evaluation/evaluate.py --runs $${RUNS:-3}

evaluate-url:  ## same, against the URL-only (black-box) demo project — see docs/WEB_SCANNING.md
	docker compose exec backend python /evaluation/evaluate.py --runs $${RUNS:-3} --project-name "URL scan only"

test: test-backend test-frontend

# Runs with SQLite by default, which skips the URL-mode DB-integration tests
# (they need real JSONB/UUID columns) — set DATABASE_URL to a real Postgres to
# include them too. See docs/WEB_SCANNING.md section 7.
test-backend:
	docker compose run --rm --no-deps -e DATABASE_URL=sqlite:// backend python -m pytest -q tests

test-frontend:
	cd frontend && npm install && npm test
