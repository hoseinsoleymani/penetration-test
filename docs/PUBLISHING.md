# Publishing checklist

1. Decide on the final GitHub repository owner and name. `README.md` uses the illustrative `OWNER/nextaudit` path; replace `OWNER` before sharing installation links.
2. Check whether **nextaudit** is an available PyPI package name. Owning a GitHub repository does not grant ownership of a PyPI name. If needed, rename the distribution in `pyproject.toml` while keeping the executable named `nextaudit`.
3. Run `git status --short`, review all tracked content, and search for credentials/host-specific targets. Use a secret scanner on the complete Git history if this is not a new repository.
4. Install with `python -m pip install -e '.[dev]'`, run `pytest -q`, run the local demo `nextaudit demo`, and build with `python -m build`.
5. Verify the generated wheel installs in a clean virtual environment, then run `nextaudit --version` and `nextaudit scan --help`.
6. Set up GitHub Actions under `.github/workflows/`, enable code scanning / Dependabot if available, and add repository topics and a description.
7. Create a new, clean repository. Do not copy old `.git` history containing sensitive inventories/reports or secrets. Keep scan output and `.env` outside version control.
8. Create a version tag and GitHub Release after tests pass. Publishing to PyPI requires a **separate** deliberate release workflow and project ownership verification; this repository does not auto-upload artifacts.

No live external website was scanned to certify this release; use the included local test fixtures. All pattern findings require manual validation.
