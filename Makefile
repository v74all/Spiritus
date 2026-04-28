.PHONY: help install dev test fmt lint type-check security clean docker-up docker-down migrate

help:
	@echo "🚀 Spiritus Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install dependencies"
	@echo "  make venv             Create virtual environment"
	@echo ""
	@echo "Development:"
	@echo "  make dev              Start development server"
	@echo "  make docker-up        Start Docker services"
	@echo "  make docker-down      Stop Docker services"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run tests with coverage"
	@echo "  make test-watch       Run tests in watch mode"
	@echo "  make test-debug       Run single test with debugging"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt              Format code with Black"
	@echo "  make lint             Lint with Ruff"
	@echo "  make type-check       Type check with MyPy"
	@echo "  make security         Run security scans"
	@echo "  make quality          Run all quality checks"
	@echo ""
	@echo "Database:"
	@echo "  make migrate          Run database migrations"
	@echo "  make migrate-create   Create new migration"
	@echo "  make migrate-status   Show migration status"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean            Clean build artifacts"
	@echo "  make build            Build Docker image"
	@echo "  make logs             View application logs"

# Setup Commands
install:
	pip install --upgrade pip setuptools wheel
	pip install -r requirements.txt
	pre-commit install

venv:
	python3 -m venv venv
	source venv/bin/activate && pip install -r requirements.txt

# Development
dev:
	uvicorn main:app --reload --host 0.0.0.0 --port 38471

dev-no-reload:
	uvicorn main:app --host 0.0.0.0 --port 38471

docker-up:
	docker-compose up -d
	@echo "✓ Services started"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Redis: localhost:6379"
	@echo "  Prometheus: localhost:9090"
	@echo "  Grafana: localhost:3000"

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Testing
test:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term-missing
	@echo "✓ Coverage report: htmlcov/index.html"

test-watch:
	ptw tests/ -- -v

test-debug:
	pytest tests/ -v --pdb

test-integration:
	pytest tests/integration/ -v

test-unit:
	pytest tests/unit/ -v

# Code Quality
fmt:
	black app/ main.py security.py models.py app_config.py
	@echo "✓ Formatted with Black"

fmt-check:
	black --check app/ main.py security.py models.py app_config.py

lint:
	ruff check --fix app/ main.py security.py models.py app_config.py
	@echo "✓ Linted with Ruff"

lint-check:
	ruff check app/ main.py security.py models.py app_config.py

type-check:
	mypy app/ main.py security.py models.py app_config.py --strict --ignore-missing-imports

security:
	@echo "🔐 Running security scans..."
	bandit -r app/ main.py security.py models.py -f screen
	@echo ""
	@echo "Running pip-audit..."
	pip-audit --desc
	@echo "✓ Security scan complete"

quality: fmt lint type-check security
	@echo "✓ All quality checks passed"

# Database
migrate:
	alembic upgrade head
	@echo "✓ Migrations applied"

migrate-create:
	@read -p "Migration name: " name; \
	alembic revision --autogenerate -m "$$name"

migrate-status:
	alembic current
	alembic branches

migrate-downgrade:
	alembic downgrade -1

# Docker Build
build:
	docker build -t spiritus:latest .
	@echo "✓ Image built: spiritus:latest"

build-no-cache:
	docker build --no-cache -t spiritus:latest .

# Utilities
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Cleaned"

logs:
	@if [ -f main.log ]; then tail -f main.log; else echo "No logs found"; fi

# Admin Commands
create-admin:
	python3 << 'EOF'
import uuid
from models import User, Base
from security import hash_password
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

engine = create_engine('postgresql://spiritus:spiritus@localhost/spiritus')
Base.metadata.create_all(engine)

session = Session(engine)
admin = User(
    id=str(uuid.uuid4()),
    name='admin',
    uuid=str(uuid.uuid4()),
    active=True,
)
admin.password_hash = hash_password('changeme')
session.add(admin)
session.commit()
print("✓ Admin user created with password: changeme")
EOF

reset-db:
	@echo "⚠️  Dropping all tables..."
	python3 << 'EOF'
from models import Base
from sqlalchemy import create_engine

engine = create_engine('postgresql://spiritus:spiritus@localhost/spiritus')
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
print("✓ Database reset")
EOF

# Deployment
deploy-local:
	docker-compose -f docker-compose.yml up -d
	docker-compose exec app alembic upgrade head
	docker-compose exec app python3 << 'EOF'
import uuid
from models import User
from security import hash_password
from sqlalchemy.orm import Session

# Create admin user
EOF
	@echo "✓ Deployed locally"

deploy-prod:
	@echo "⚠️  Production deployment. Are you sure? (ctrl+C to cancel)"
	@read -p "Enter deployment confirmation: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		docker build -t spiritus:latest .; \
		docker-compose up -d; \
		echo "✓ Deployed to production"; \
	else \
		echo "Deployment cancelled"; \
	fi

# Documentation
docs:
	@echo "📚 Documentation"
	@echo "  README.md              - Project overview"
	@echo "  SECURITY.md            - Security architecture"
	@echo "  MIGRATION.md           - v1.x → v2.0 upgrade"
	@echo "  CONTRIBUTING.md        - Developer guide"
	@echo "  ROADMAP.md             - Feature roadmap"
	@echo "  DEPLOYMENT.md          - Deployment guide"
	@echo "  API.md                 - API reference"

# CI/CD
ci: quality test
	@echo "✓ CI pipeline passed"

pre-commit-install:
	pre-commit install
	@echo "✓ Pre-commit hooks installed"

pre-commit-run:
	pre-commit run --all-files
	@echo "✓ Pre-commit hooks executed"

# Info
info:
	@python3 << 'EOF'
import sys
print(f"Python: {sys.version}")
EOF
	@pip show -f fastapi | grep Version
	@pip show -f sqlalchemy | grep Version
	@docker --version
	@docker-compose --version
