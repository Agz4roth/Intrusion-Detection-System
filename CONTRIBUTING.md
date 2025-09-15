Contributing to Intrusion Detection System (IDS)

Thanks for your interest in contributing! This project welcomes security researchers, developers, and enthusiasts who want to improve threat detection tools.

---

Ways to contribute

- Report bugs via GitHub Issues
- Suggest new detection rules or features
- Improve test coverage and reliability
- Enhance documentation and examples
- Help review security-related changes

---

Development setup

1. Fork and clone the repository
2. Create a virtual environment:
   ```
   python3 -m venv .venv && source .venv/bin/activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

---

Coding guidelines

- Python 3.11+
- Use modular, readable code
- Add unit tests for new logic
- Use type hints where appropriate
- Follow PEP8 formatting (auto-formatting with black is encouraged)

---

Commit style

Use Conventional Commits when possible:

- feat: for new features
- fix: for bug fixes
- docs: for documentation changes
- test: for adding/modifying tests
- refactor: for code restructuring
- chore: for maintenance tasks

Example:
```
git commit -m "feat: add rule for SSH brute force detection"
```

---

Pull requests

- Keep PRs focused and atomic
- Link related issues (e.g., Fixes #42)
- Update documentation if behavior changes
- Ensure tests pass before submitting

---

Thank you

Your contributions help make this project better for everyone. I appreciate your time, expertise, and ideas!


---