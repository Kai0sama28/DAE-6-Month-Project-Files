"""Run the triage API with a single Uvicorn worker."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("TRIAGE_API_HOST", "127.0.0.1")
    port = int(os.environ.get("TRIAGE_API_PORT", "8080"))
    uvicorn.run(
        "services.triage_api.app:app",
        host=host,
        port=port,
        workers=1,
        reload=False,
    )


if __name__ == "__main__":
    main()
