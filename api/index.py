from app import app
from asgiref.wsgi import WsgiToAsgi

# Vercel은 handler라는 엔트리포인트를 찾음
handler = WsgiToAsgi(app)
