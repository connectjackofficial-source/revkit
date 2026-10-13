# Contributing

Thanks for considering a contribution to revkit. Small, focused pull
requests are very welcome.

## Ground rules

- **Zero dependencies stays zero.** New code must use only the Python
  standard library. If you need `numpy`, the idea probably belongs in an
  optional extra or a separate project.
- **Keep modules small.** If a file passes ~400 lines, split the feature
  into its own module (`pe.py`, `detect.py`, `strings.py`, `entropy.py`
  are the model).
- **Tests are script-style.** No pytest required: every `tests/test_*.py`
  has a `__main__` block that runs and prints. Run them with:

  ```console
  $env:PYTHONPATH = "."
  python -u tests\test_headers.py
  python -u tests\test_sections.py
  python -u tests\test_imports.py
  python -u tests\test_exports.py
  python -u tests\test_strings.py
  python -u tests\test_detect.py
  python -u tests\test_entropy.py
  python -u tests\test_cli.py
  ```

- **Test on real binaries and synthetic bytes.** Real system files
  (`kernel32.dll`) prove the parser works on ground truth; synthetic
  images (built with `struct.pack`) pin down edge cases deterministically.
- **Update docs with behavior.** New CLI flags go into `README.md` usage,
  new features into `CHANGELOG.md` under `[Unreleased]`.

## Process

1. Open an issue describing the change (unless it is tiny).
2. Fork, branch off `main`, keep commits small and self-contained.
3. Run the full test suite; all must pass.
4. Open a pull request; mention what you tested and on which files.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy.
