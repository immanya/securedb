import inspect
import json
import re
from datetime import datetime, date
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.middleware.cors import CORSMiddleware
from starlette.testclient import TestClient
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException

# Re-export status and TestClient
__all__ = [
    "FastAPI",
    "APIRouter",
    "Depends",
    "Query",
    "HTTPException",
    "HTTPBearer",
    "HTTPAuthorizationCredentials",
    "status",
    "TestClient",
]

class HTTPException(StarletteHTTPException):
    def __init__(self, status_code: int, detail: Any = None, headers: Optional[Dict[str, str]] = None):
        super().__init__(status_code=status_code, detail=detail)
        self.headers = headers or {}


class Depends:
    def __init__(self, dependency: Optional[Callable] = None):
        self.dependency = dependency


class Query:
    def __init__(self, default: Any = ..., description: Optional[str] = None, ge: Optional[int] = None, le: Optional[int] = None):
        self.default = default
        self.description = description
        self.ge = ge
        self.le = le


class HTTPAuthorizationCredentials:
    def __init__(self, scheme: str, credentials: str):
        self.scheme = scheme
        self.credentials = credentials


class HTTPBearer:
    def __init__(self, auto_error: bool = True):
        self.auto_error = auto_error

    def __call__(self, request: Request) -> Optional[HTTPAuthorizationCredentials]:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            if self.auto_error:
                raise HTTPException(status_code=401, detail="Not authenticated")
            return None
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            if self.auto_error:
                raise HTTPException(status_code=401, detail="Invalid authentication credentials")
            return None
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=parts[1])


def _json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    raise TypeError(f"Type {type(obj)} not serializable")


def _serialize_response(data: Any, response_model: Any = None) -> Any:
    """Convert response objects to JSON serializable structures."""
    if data is None:
        return None
    if isinstance(data, (str, int, float, bool)):
        return data

    if isinstance(data, list):
        out = []
        for item in data:
            if response_model:
                try:
                    # If response_model is List[X], get X
                    target_cls = getattr(response_model, "__args__", [response_model])[0]
                    if hasattr(target_cls, "model_validate"):
                        item = target_cls.model_validate(item).model_dump()
                    elif hasattr(target_cls, "from_orm"):
                        item = target_cls.from_orm(item).dict()
                except Exception:
                    pass
            out.append(_serialize_response(item))
        return out

    if response_model and hasattr(response_model, "model_validate"):
        try:
            return response_model.model_validate(data).model_dump()
        except Exception:
            pass

    if hasattr(data, "model_dump"):
        return data.model_dump()
    if hasattr(data, "dict"):
        return data.dict()
    if isinstance(data, dict):
        return {k: _serialize_response(v) for k, v in data.items()}
    if hasattr(data, "__dict__"):
        return {k: _serialize_response(v) for k, v in data.__dict__.items() if not k.startswith("_")}

    return data


class APIRouter:
    def __init__(self, prefix: str = "", tags: Optional[List[str]] = None):
        self.prefix = prefix
        self.tags = tags or []
        self.routes: List[Tuple[str, str, Callable, Optional[Any], int]] = []  # (method, path, fn, resp_model, status_code)

    def add_api_route(self, path: str, endpoint: Callable, methods: List[str], response_model: Optional[Any] = None, status_code: int = 200):
        for method in methods:
            full_path = self.prefix + path
            self.routes.append((method.upper(), full_path, endpoint, response_model, status_code))

    def get(self, path: str, response_model: Optional[Any] = None, status_code: int = 200):
        def decorator(fn):
            self.add_api_route(path, fn, ["GET"], response_model, status_code)
            return fn
        return decorator

    def post(self, path: str, response_model: Optional[Any] = None, status_code: int = 200):
        def decorator(fn):
            self.add_api_route(path, fn, ["POST"], response_model, status_code)
            return fn
        return decorator

    def delete(self, path: str, response_model: Optional[Any] = None, status_code: int = 200):
        def decorator(fn):
            self.add_api_route(path, fn, ["DELETE"], response_model, status_code)
            return fn
        return decorator


class FastAPI:
    def __init__(self, title: str = "", version: str = "", description: str = "", lifespan: Optional[Any] = None):
        self.title = title
        self.version = version
        self.description = description
        self.lifespan = lifespan
        self.router = APIRouter()
        self.dependency_overrides: Dict[Callable, Callable] = {}
        self.middleware_stack: List[Tuple[Any, Dict]] = []
        self._mounts: List[Tuple[str, Any, Optional[str]]] = []
        self._starlette_app: Optional[Starlette] = None

    def mount(self, path: str, app: Any, name: Optional[str] = None):
        self._mounts.append((path, app, name))

    def add_middleware(self, middleware_class: Any, **kwargs):
        self.middleware_stack.append((middleware_class, kwargs))

    def include_router(self, router: APIRouter, prefix: str = ""):
        for method, path, endpoint, resp_model, status_code in router.routes:
            full_path = prefix + path
            self.router.add_api_route(full_path, endpoint, [method], resp_model, status_code)

    def get(self, path: str, response_model: Optional[Any] = None, status_code: int = 200):
        return self.router.get(path, response_model, status_code)

    def post(self, path: str, response_model: Optional[Any] = None, status_code: int = 200):
        return self.router.post(path, response_model, status_code)

    def delete(self, path: str, response_model: Optional[Any] = None, status_code: int = 200):
        return self.router.delete(path, response_model, status_code)

    def _resolve_dependency(self, dep_fn: Callable, request: Request, cleanup_list: List[Any]) -> Any:
        # Check overrides
        target_fn = self.dependency_overrides.get(dep_fn, dep_fn)
        
        # If callable is an instance of HTTPBearer
        if isinstance(target_fn, HTTPBearer):
            return target_fn(request)

        # Inspect parameters of target_fn
        sig = inspect.signature(target_fn)
        args = {}
        for param_name, param in sig.parameters.items():
            if isinstance(param.default, Depends):
                args[param_name] = self._resolve_dependency(param.default.dependency, request, cleanup_list)
            elif param.annotation is Request or param_name == "request":
                args[param_name] = request

        result = target_fn(**args)
        
        # Generator dependency support (e.g., get_db yields session)
        if inspect.isgenerator(result):
            gen = result
            cleanup_list.append(gen)
            return next(gen)
            
        return result

    def _build_handler(self, endpoint: Callable, response_model: Optional[Any], default_status_code: int):
        async def handler(request: Request) -> Response:
            cleanup_list: List[Any] = []
            try:
                sig = inspect.signature(endpoint)
                kwargs = {}
                
                body_data = None
                content_type = request.headers.get("content-type", "")
                if "application/json" in content_type:
                    try:
                        body_data = await request.json()
                    except Exception:
                        body_data = {}

                for param_name, param in sig.parameters.items():
                    # 1. Dependency
                    if isinstance(param.default, Depends):
                        kwargs[param_name] = self._resolve_dependency(param.default.dependency, request, cleanup_list)
                    # 2. Path parameter
                    elif param_name in request.path_params:
                        raw_val = request.path_params[param_name]
                        if param.annotation is int:
                            kwargs[param_name] = int(raw_val)
                        else:
                            kwargs[param_name] = raw_val
                    # 3. Query parameter
                    elif isinstance(param.default, Query) or (param_name in request.query_params):
                        raw_val = request.query_params.get(param_name)
                        if raw_val is None:
                            q_def = param.default.default if isinstance(param.default, Query) else param.default
                            kwargs[param_name] = None if q_def is ... else q_def
                        else:
                            if param.annotation is bool or (isinstance(param.default, Query) and isinstance(param.default.default, bool)):
                                kwargs[param_name] = raw_val.lower() in ("true", "1", "yes")
                            elif param.annotation is int:
                                kwargs[param_name] = int(raw_val)
                            else:
                                kwargs[param_name] = raw_val
                    # 4. JSON Body parameter
                    elif hasattr(param.annotation, "__mro__") and any(b.__name__ == "BaseModel" for b in param.annotation.__mro__):
                        if body_data is None:
                            try:
                                body_data = await request.json()
                            except Exception:
                                body_data = {}
                        try:
                            kwargs[param_name] = param.annotation(**body_data)
                        except Exception as val_err:
                            raise HTTPException(status_code=400, detail=str(val_err))
                    elif param.annotation is Request or param_name == "request":
                        kwargs[param_name] = request
                    elif param.default is not inspect.Parameter.empty:
                        kwargs[param_name] = param.default

                # Call endpoint
                if inspect.iscoroutinefunction(endpoint):
                    res = await endpoint(**kwargs)
                else:
                    res = endpoint(**kwargs)

                if isinstance(res, Response):
                    return res

                # Serialize response
                serialized = _serialize_response(res, response_model)
                json_str = json.dumps(serialized, default=_json_serial)
                return Response(content=json_str, media_type="application/json", status_code=default_status_code)

            except HTTPException as http_exc:
                content = json.dumps({"detail": http_exc.detail})
                return Response(content=content, media_type="application/json", status_code=http_exc.status_code, headers=http_exc.headers)
            except Exception as e:
                content = json.dumps({"detail": str(e)})
                return Response(content=content, media_type="application/json", status_code=500)
            finally:
                for gen in cleanup_list:
                    try:
                        next(gen, None)
                    except StopIteration:
                        pass
                    except Exception:
                        pass

        return handler

    def _ensure_starlette(self):
        from starlette.routing import Mount
        starlette_routes = []
        for method, path, endpoint, resp_model, status_code in self.router.routes:
            handler = self._build_handler(endpoint, resp_model, status_code)
            starlette_routes.append(Route(path, handler, methods=[method]))

        for path, subapp, name in self._mounts:
            starlette_routes.append(Mount(path, app=subapp, name=name))

        app = Starlette(routes=starlette_routes, lifespan=self.lifespan)
        for mw_cls, mw_kwargs in self.middleware_stack:
            app.add_middleware(mw_cls, **mw_kwargs)
        self._starlette_app = app
        return app

    async def __call__(self, scope, receive, send):
        if self._starlette_app is None:
            self._ensure_starlette()
        await self._starlette_app(scope, receive, send)
