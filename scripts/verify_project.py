"""Run software checks and persist evidence; does not run a malware lab."""
from __future__ import annotations

import argparse
import ast
import compileall
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/reports/software_validation/latest.json")
    args = parser.parse_args()
    compiled = all([compileall.compile_dir(ROOT / folder, quiet=1) for folder in ("apps", "process_guard", "scripts", "tests")])
    notebook_checks = []
    for path in sorted((ROOT / "notebooks").glob("*.ipynb")):
        try:
            notebook = json.loads(path.read_text(encoding="utf-8"))
            for index, cell in enumerate(notebook["cells"]):
                if cell["cell_type"] == "code":
                    source = "".join(cell["source"])
                    if any(line.lstrip().startswith(("%", "!")) for line in source.splitlines()):
                        continue  # IPython syntax is not parseable by Python ast
                    ast.parse(source, filename=f"{path.name}:cell{index}")
            notebook_checks.append({"path": str(path.relative_to(ROOT)), "code_syntax": "passed"})
        except (OSError, ValueError, KeyError, SyntaxError) as exc:
            notebook_checks.append({"path": str(path.relative_to(ROOT)), "code_syntax": "failed", "error": str(exc)})
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and compiled and all(row["code_syntax"] == "passed" for row in notebook_checks)
    versions = {}
    for package in ("psutil", "pandas", "numpy", "scikit-learn", "joblib", "matplotlib"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    evidence = {"schema_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "status": "passed" if passed else "failed", "python": platform.python_version(),
                "platform": platform.platform(), "library_versions": versions,
                "compilation_passed": compiled, "notebook_checks": notebook_checks,
                "tests_run": result.testsRun, "failures": [test.id() for test, _ in result.failures],
                "errors": [test.id() for test, _ in result.errors], "skipped": len(result.skipped),
                "vm_lab_validated": False,
                "scope": "Software tests with temporary synthetic fixtures and read-only collector checks; no PID lab accuracy claim. Notebooks were syntax-checked, not trained on missing lab data."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Software validation: {args.output.resolve()}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
