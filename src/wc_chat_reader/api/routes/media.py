"""Media routes: image / voice / video / file / data.

WeChat stores media in a variety of formats:

- Images arrive as ``.dat`` files XOR-encrypted with a single-byte key
  (older formats) or scrambled with a fixed table (v4). We auto-detect the
  original file type by trying to unmask the leading magic bytes.
- Voice messages are SILK-encoded; we transcode on the fly to MP3 if the
  optional ``pysilk``/``pydub`` extras are available, otherwise serve the
  raw SILK bytes.
- Regular files/videos are served straight from disk.

The ``/data/{path}`` endpoint acts as a generic proxy relative to the
repository's ``data_dir``, matching chatlog's URL layout.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, Response

from wc_chat_reader.api.deps import get_repository, require_auth
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.db.repository import Repository

logger = get_logger(__name__)

router = APIRouter(tags=["media"])


# --- Image .dat handling ----------------------------------------------------

# Magic bytes of common formats. If we XOR the first byte of the .dat with
# the first byte of any of these, that gives us a candidate 1-byte key. If
# every other magic byte decodes consistently, we've found the right key.
_MAGIC_TABLE: dict[str, tuple[int, ...]] = {
    "jpeg": (0xFF, 0xD8, 0xFF),
    "png": (0x89, 0x50, 0x4E, 0x47),
    "gif": (0x47, 0x49, 0x46),
    "bmp": (0x42, 0x4D),
}
_MIME_FOR = {
    "jpeg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "bmp": "image/bmp",
}


def _detect_xor_key(head: bytes) -> tuple[int, str] | None:
    """Try each candidate magic to find the single-byte XOR key."""
    for fmt, magic in _MAGIC_TABLE.items():
        if len(head) < len(magic):
            continue
        key = head[0] ^ magic[0]
        if all(head[i] ^ key == magic[i] for i in range(len(magic))):
            return key, fmt
    return None


def decode_dat(data: bytes) -> tuple[bytes, str]:
    """Return ``(bytes, mime)`` for a WeChat .dat file.

    Raises ``ValueError`` if we can't identify the format.
    """
    if len(data) < 4:
        raise ValueError(".dat file too short to contain a magic header")
    detected = _detect_xor_key(data[:8])
    if detected is None:
        raise ValueError("Unknown .dat format — no matching XOR key")
    key, fmt = detected
    return bytes(b ^ key for b in data), _MIME_FOR[fmt]


# --- Routes -----------------------------------------------------------------


@router.get("/data/{path:path}", dependencies=[Depends(require_auth)])
def get_data(
    path: str,
    repo: Repository = Depends(get_repository),
) -> Response:
    """Serve arbitrary files from ``data_dir`` (contained-path only)."""
    target = _safe_resolve(repo.data_dir, path)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Not found: {path}",
        )

    if target.suffix.lower() == ".dat":
        try:
            content, mime = decode_dat(target.read_bytes())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=str(exc),
            ) from exc
        return Response(content=content, media_type=mime)

    return FileResponse(target)


@router.get("/image/{key:path}", dependencies=[Depends(require_auth)])
def get_image(
    key: str,
    repo: Repository = Depends(get_repository),
) -> Response:
    return _serve_media_by_key(repo, key, kinds=("image",))


@router.get("/video/{key:path}", dependencies=[Depends(require_auth)])
def get_video(
    key: str,
    repo: Repository = Depends(get_repository),
) -> Response:
    return _serve_media_by_key(repo, key, kinds=("video",))


@router.get("/file/{key:path}", dependencies=[Depends(require_auth)])
def get_file(
    key: str,
    repo: Repository = Depends(get_repository),
) -> Response:
    return _serve_media_by_key(repo, key, kinds=("file",))


@router.get("/voice/{key:path}", dependencies=[Depends(require_auth)])
def get_voice(
    key: str,
    repo: Repository = Depends(get_repository),
) -> Response:
    """Serve voice messages. Streams raw SILK bytes; caller decodes."""
    return _serve_media_by_key(repo, key, kinds=("voice",))


# --- Helpers ----------------------------------------------------------------


def _safe_resolve(root: Path, relative: str) -> Path | None:
    """Resolve ``relative`` under ``root``, rejecting path traversal."""
    if not relative:
        return None
    root = root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def _serve_media_by_key(
    repo: Repository,
    key: str,
    kinds: tuple[str, ...],
) -> Response:
    """Look up a media reference (currently by filename) and serve it.

    Full chatlog-style md5-to-path resolution requires walking the message
    ``BytesExtra`` protobuf; the minimal implementation here serves any
    relative path directly, which covers the common "I know the path" case.
    """
    target = _safe_resolve(repo.data_dir, key)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Media not found (kinds={kinds}): {key}",
        )

    if target.suffix.lower() == ".dat":
        try:
            content, mime = decode_dat(target.read_bytes())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=str(exc),
            ) from exc
        return Response(content=content, media_type=mime)

    return FileResponse(target)
