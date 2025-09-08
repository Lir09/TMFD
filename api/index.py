from app import app
from asgiref.wsgi import WsgiToAsgi

# Vercel은 handler를 찾음
handler = WsgiToAsgi(app)
