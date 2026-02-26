"""
Production WSGI entry-point for HoursLog.

Usage (Windows):
    python wsgi.py

Or via waitress-serve:
    waitress-serve --port=8080 --threads=4 wsgi:app

The app is wrapped with WhiteNoise so static files (CSS, JS, images) are
served efficiently without a separate web server like nginx.
"""

import os

# Default to production when running this file directly.
os.environ.setdefault('FLASK_ENV', 'production')

from app import create_app  # noqa: E402
from whitenoise import WhiteNoise  # noqa: E402

app = create_app()

# Serve /static files via WhiteNoise middleware.
app.wsgi_app = WhiteNoise(
    app.wsgi_app,
    root=os.path.join(os.path.dirname(__file__), 'app', 'static'),
    prefix='static/',
)

if __name__ == '__main__':
    from waitress import serve

    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))
    threads = int(os.environ.get('WAITRESS_THREADS', 4))

    print(f'Starting HoursLog production server on {host}:{port} '
          f'(threads={threads})')
    serve(app, host=host, port=port, threads=threads)
