def main() -> int:
    try:
        import mcp  # noqa: F401
        import pydantic  # noqa: F401
        import httpx  # noqa: F401
    except Exception as e:
        print("dependency import failed:", e)
        return 1

    print("mcp-trust-gateway deps import: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
