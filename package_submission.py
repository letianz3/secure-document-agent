"""Build D1 using an explicit allowlist; never package runtime logs or credentials."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED


def main():
    root = Path(__file__).resolve().parent
    selected = [root / name for name in ["README.md", "DEMO.md", "AI_USAGE.md", "FLOWCHART.md", "requirements.txt",
                ".gitignore", "verify.py", "package_submission.py", "configure_key.py",
                "live_verify.py", "verify_guard.py", "data/documents.json", "evidence/guard_results.json",
                "evidence/test_results.txt", "evidence/offline_demo_results.json", "evidence/offline_audit.jsonl"]]
    selected += sorted((root / "secure_agent").glob("*.py"))
    selected += sorted((root / "tests").glob("test_*.py"))
    live_evidence = root / "evidence" / "live_results.json"
    if live_evidence.is_file():
        selected.append(live_evidence)
    for path in selected:
        if not path.is_file():
            raise SystemExit(f"Missing {path.relative_to(root)}; run python verify.py first.")
    destination = root / "dist" / "HW1_secure_document_agent_D1.zip"
    destination.parent.mkdir(exist_ok=True)
    with ZipFile(destination, "w", ZIP_DEFLATED) as bundle:
        for path in selected:
            bundle.write(path, path.relative_to(root).as_posix())
    with ZipFile(destination) as bundle:
        if bundle.testzip() is not None:
            raise SystemExit("ZIP integrity check failed")
    print(f"Created {destination} ({len(selected)} files)")


if __name__ == "__main__":
    main()
