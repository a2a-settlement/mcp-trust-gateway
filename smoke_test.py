"""Smoke test — verify all required dependencies import correctly."""


def main() -> int:
    errors: list[str] = []
    for mod in ("mcp", "httpx", "pydantic", "jwt", "starlette", "uvicorn"):
        try:
            __import__(mod)
        except ImportError as exc:
            errors.append(f"  {mod}: {exc}")

    if errors:
        print("dependency import failures:")
        print("\n".join(errors))
        return 1

    print("mcp-trust-gateway deps import: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
