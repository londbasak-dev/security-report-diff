# Contributing

Use Python 3.10 or newer. Create a virtual environment, run `python -m pip
install -e .`, then `python -m unittest discover -s tests -v` from this directory.
The package uses only Python's standard library at runtime.

Keep changes small and document input/output behavior and limitations. Add a
focused regression test for parser, matching or privacy behavior. Tests and
examples must be newly generated synthetic data. Do not commit real reports,
APKs, manifests, paths containing personal names, tokens or credentials.

Before proposing a change, run the full test suite, exercise the sample CLI,
and inspect the staged diff for private data. Do not add badges or claims of
third-party verification unless independently substantiated.
