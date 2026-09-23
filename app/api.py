"""FastAPI 入口：受保护资源与认证端点（骨架）。"""

from __future__ import annotations

from fastapi import FastAPI

from .service import AuthService


def create_app(service: AuthService | None = None) -> FastAPI:
    raise NotImplementedError
