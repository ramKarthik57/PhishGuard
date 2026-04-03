# Contributing to PhishGuard

First off, thank you for considering contributing to PhishGuard! It's people like you that make it such a great tool.

## Where to Start?

- **Did you find a bug?** Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/phishguard/phishguard/issues). If you're unable to find an open issue addressing the problem, open a new one.
- **Have a feature request?** Create a new issue describing your idea. Include clear use cases.
- **Want to write code?** Great! First, review the architecture overview in `README.md`.

## Development Setup

1. Fork the repository and clone it locally.
2. We recommend using a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the test suite to ensure everything is working:
   ```bash
   python -m pytest tests/
   ```

## Adding Detection Rules
To add a new rule, modify `detector.py`. 
Each rule must be added to the `RULES` dictionary and have:
1. A unique `id`.
2. A weight logic (`max_weight`).
3. An `execute()` lambda or function.
4. An entry in the Explainable AI mapping `config.py`.

## Adding Custom Threat Intelligence
To add a new threat intelligence feed, create a new file in `services/` and integrate it into `detector.py` under the `_evaluate_threat_intel()` method.

## Pull Requests
- Keep your PRs focused on a single feature or bug fix.
- Ensure all tests pass.
- Write tests for new features.
- Adhere to PEP8 styling standards (we use `flake8`).
