from app import app
from asgiref.wsgi import WsgiToAsgi

handler = WsgiToAsgi(app)  # Vercel이 찾는 엔트리포인트
