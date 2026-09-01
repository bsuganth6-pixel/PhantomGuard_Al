"""
index.py
---------
Vercel entrypoint. Vercel's Python runtime looks for a Flask instance
named `app` at one of a few conventional root filenames (app.py, index.py,
server.py, main.py, wsgi.py, asgi.py). The real app lives in web/app.py
(so local dev / Docker via `python web/app.py` or gunicorn is unchanged);
this file just re-exports it so Vercel's zero-config detection finds it.

Nothing else belongs in here -- no app.run(), Vercel imports `app`
directly and calls it as a WSGI callable.
"""

from web.app import app  # noqa: F401
