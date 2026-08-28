"""Entry point for ``python -m wc_chat_reader.cli``.

Importing :mod:`wc_chat_reader.cli.main` directly via ``python -m`` warns
because the package ``__init__`` already imports it; routing through the
package avoids the double-import and is the documented invocation.
"""

from wc_chat_reader.cli.main import app

if __name__ == "__main__":
    app()
