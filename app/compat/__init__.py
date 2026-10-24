# Universal compatibility layer for environments with restricted C-extension policies

# Pydantic loader
try:
    from pydantic import BaseModel, Field, field_validator
except Exception:
    from app.compat.pydantic_shim import BaseModel, Field, field_validator

# FastAPI loader
try:
    from fastapi import FastAPI, APIRouter, Depends, Query, HTTPException, status
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.testclient import TestClient
except Exception:
    from app.compat.fastapi_shim import (
        FastAPI,
        APIRouter,
        Depends,
        Query,
        HTTPException,
        HTTPBearer,
        HTTPAuthorizationCredentials,
        status,
        CORSMiddleware,
        TestClient,
    )

__all__ = [
    "BaseModel",
    "Field",
    "field_validator",
    "FastAPI",
    "APIRouter",
    "Depends",
    "Query",
    "HTTPException",
    "status",
    "HTTPBearer",
    "HTTPAuthorizationCredentials",
    "CORSMiddleware",
    "TestClient",
]
