# Contributing

Thanks for your interest in **clawkit**! Contributions are welcome.

## Getting Started

1. Fork the repository.
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/clawkit.git
   cd clawkit
   ```
3. Install in editable mode:
   ```bash
   pip install -e .
   ```

## Development Guidelines

- **Zero dependencies** — clawkit uses only the Python stdlib. Do not add external packages.
- **Python 3.8+** — keep compatibility.
- **Style** — follow [PEP 8](https://peps.python.org/pep-0008/) with ~88 char lines.
- **Consistent CLI** — new commands follow the existing pattern:
  - `register(sub)` — add subparser with `sub.add_parser()`
  - `run(args)` — implement the command logic
  - Register the module in `clawkit/cli.py` `COMMANDS` dict

## Testing

Run tests with pytest:

```bash
pytest tests/ -v
```

Add tests for any new functionality under `tests/`.

## Submitting Changes

1. Create a feature branch: `git checkout -b my-feature`
2. Commit your changes with clear messages.
3. Push and open a Pull Request.

## Code of Conduct

Be respectful and constructive. Harassment or toxic behaviour will not be tolerated.

## Questions?

Open an issue or discussion on GitHub.
