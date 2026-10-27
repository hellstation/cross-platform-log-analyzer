import uvicorn

from sentineltrace.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "sentineltrace.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )


if __name__ == "__main__":
    main()
