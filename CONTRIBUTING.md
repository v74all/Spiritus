# Contributing to Spiritus

We welcome contributions from the community! This document explains our development process, code standards, and how to contribute.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- PostgreSQL 12+
- Redis 6+
- Docker & Docker Compose
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/v74all/Spiritus.git
cd Spiritus

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install pytest pytest-cov mypy ruff black bandit semgrep

# Start Docker services
docker-compose up -d db redis

# Run migrations
alembic upgrade head

# Start development server
uvicorn main:app --reload --host 0.0.0.0 --port 38471
```

---

## 📋 Code Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with these tools:

#### Formatting (Black)
```bash
black app/ main.py security.py models.py
```

#### Linting (Ruff)
```bash
ruff check --fix app/ main.py security.py models.py
```

#### Type Checking (MyPy)
```bash
mypy app/ main.py security.py models.py --strict
```

#### Security (Bandit)
```bash
bandit -r app/ main.py security.py
```

### Pre-commit Hook Setup

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/psf/black
    rev: 23.11.0
    hooks:
      - id: black
        language_version: python3.11
  
  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: v0.1.0
    hooks:
      - id: ruff
        args: [--fix]
  
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
        args: [--strict, --ignore-missing-imports]
  
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: [-c, .bandit]
EOF

# Install hooks
pre-commit install

# Run on all files
pre-commit run --all-files
```

---

## 🧪 Testing

### Running Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=app --cov-report=html

# Specific test file
pytest tests/test_auth.py -v

# Specific test function
pytest tests/test_auth.py::test_login_success -v

# Watch mode (requires pytest-watch)
ptw tests/ -- -v
```

### Writing Tests

```python
# tests/test_auth.py
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

@pytest.fixture
def admin_token():
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "password"}
    )
    return response.json()["access_token"]

def test_login_success():
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "password"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_protected_endpoint(admin_token):
    response = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200

def test_invalid_credentials():
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 401
```

### Coverage Requirements

- Minimum: 70%
- Target: 85%+
- Critical paths (auth, security): 95%+

```bash
# Generate HTML coverage report
pytest tests/ --cov=app --cov-report=html
open htmlcov/index.html
```

---

## 📝 Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Test addition/modification
- `security`: Security fix
- `chore`: Build, dependency update

### Examples

```
feat(auth): add TOTP 2FA support

- Implement TOTP secret generation
- Add token verification endpoint
- Update audit logging

Fixes #123

feat(api): new /api/admin/analytics endpoint

docs: update database setup guide

fix(security): prevent timing attack in password verification

security(headers): add COOP/CORP/COEP headers
```

---

## 🔄 Pull Request Process

### Before Submitting PR

1. **Fork the repository**
```bash
git clone https://github.com/YOUR_USERNAME/Spiritus.git
cd Spiritus
```

2. **Create feature branch**
```bash
git checkout -b feature/your-feature-name
```

3. **Make changes**
```bash
# Follow code standards
make fmt  # Format code
make lint  # Lint
make test  # Run tests
```

4. **Commit with conventional commits**
```bash
git commit -m "feat(scope): description"
```

5. **Push to fork**
```bash
git push origin feature/your-feature-name
```

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests passed
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Type hints added
- [ ] Tests pass (pytest)
- [ ] Coverage maintained (>70%)
- [ ] Docstrings updated
- [ ] No new security issues
- [ ] Documentation updated

## Closes
Closes #123
```

---

## 🚨 Security Contributions

For security vulnerabilities:

1. **DO NOT** create public GitHub issue
2. **Email**: security@example.com with details
3. **Timeline**: We aim to respond within 48 hours
4. **Fixes**: Released as patch version

---

## 📚 Documentation

### Adding Documentation

- Update relevant `.md` files
- Add docstrings to Python functions
- Include code examples where applicable
- Update API docs if endpoints changed

### Documentation Format

```python
def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create JWT access token.
    
    Args:
        data: Claims to include in token
        expires_delta: Custom expiration (default: from settings)
    
    Returns:
        JWT token string
    
    Raises:
        ValueError: If data is empty
    
    Example:
        >>> token = create_access_token({"sub": "user123"})
        >>> verify_token(token)
        {'sub': 'user123', 'exp': 1234567890, 'type': 'access'}
    """
```

---

## 🐛 Reporting Issues

### Bug Report Template

```markdown
## Description
Clear description of the bug

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.0]
- Spiritus Version: [e.g., v2.0.0]

## Logs
```
Error output here
```

## Possible Solution
[Optional] Suggested fix
```

---

## 💬 Discussion & Feedback

- **GitHub Discussions**: Ask questions, share ideas
- **Issues**: Bug reports, feature requests
- **Slack/Discord**: Real-time chat (if available)

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## 🎯 Development Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and priorities.

---

## 🙏 Thank You

Thank you for contributing to Spiritus! Your effort helps make VPN technology more accessible and secure.
