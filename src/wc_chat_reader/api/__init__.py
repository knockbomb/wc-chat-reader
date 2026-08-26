"""FastAPI HTTP layer.

- ``main`` — application factory (``create_app``), lifecycle hooks.
- ``deps`` — request-scoped dependencies (repository, auth).
- ``routes`` — REST endpoints mirroring chatlog's URL shape.
- ``schemas`` — request/response models.
"""

from wc_chat_reader.api.main import create_app

__all__ = ["create_app"]
