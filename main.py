"""服务入口：uvicorn main:app"""

from auth.app import build_default_service, create_app

service = build_default_service()
app = create_app(service)
