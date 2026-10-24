import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, get_origin, get_args

class FieldInfo:
    def __init__(self, default=..., min_length=None, max_length=None, ge=None, le=None, pattern=None, description=None):
        self.default = default
        self.min_length = min_length
        self.max_length = max_length
        self.ge = ge
        self.le = le
        self.pattern = pattern
        self.description = description

def Field(default=..., min_length=None, max_length=None, ge=None, le=None, pattern=None, description=None):
    return FieldInfo(
        default=default,
        min_length=min_length,
        max_length=max_length,
        ge=ge,
        le=le,
        pattern=pattern,
        description=description
    )

def field_validator(*field_names):
    def decorator(fn):
        fn.__validator_fields__ = field_names
        return fn
    return decorator


class BaseModel:
    class Config:
        from_attributes = False

    def __init__(self, **kwargs):
        # Collect validators from class hierarchy
        validators = {}
        for attr_name in dir(self.__class__):
            try:
                attr = getattr(self.__class__, attr_name)
                if hasattr(attr, "__validator_fields__"):
                    for f in attr.__validator_fields__:
                        validators.setdefault(f, []).append(attr)
            except Exception:
                pass

        # Inspect class attributes and type hints from class hierarchy
        hints = {}
        for cls in reversed(self.__class__.__mro__):
            hints.update(getattr(cls, "__annotations__", {}))
        
        # If class has default attributes not in annotations
        for k in dir(self.__class__):
            if not k.startswith("_") and k != "Config" and k not in hints:
                hints[k] = Any

        for name, hint in hints.items():
            field_def = getattr(self.__class__, name, ...)
            
            if name in kwargs:
                val = kwargs[name]
            elif isinstance(field_def, FieldInfo) and field_def.default is not ...:
                val = field_def.default
            elif field_def is not ... and not isinstance(field_def, FieldInfo):
                val = field_def
            else:
                # Check if Optional
                origin = get_origin(hint)
                args = get_args(hint)
                if origin is Optional or (origin is type(Optional) and type(None) in args) or type(None) in args:
                    val = None
                else:
                    raise ValueError(f"Field '{name}' is required")

            # Field constraint validations
            if isinstance(field_def, FieldInfo):
                if val is not None:
                    if field_def.min_length is not None and len(val) < field_def.min_length:
                        raise ValueError(f"Field '{name}' must have at least {field_def.min_length} characters")
                    if field_def.max_length is not None and len(val) > field_def.max_length:
                        raise ValueError(f"Field '{name}' must have at most {field_def.max_length} characters")
                    if field_def.ge is not None and val < field_def.ge:
                        raise ValueError(f"Field '{name}' must be >= {field_def.ge}")
                    if field_def.le is not None and val > field_def.le:
                        raise ValueError(f"Field '{name}' must be <= {field_def.le}")
                    if field_def.pattern is not None and not re.match(field_def.pattern, str(val)):
                        raise ValueError(f"Field '{name}' does not match pattern {field_def.pattern}")

            # Run custom field validators
            if name in validators and val is not None:
                for validator in validators[name]:
                    val = validator(self.__class__, val)

            setattr(self, name, val)

    def model_dump(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        out = {}
        hints = {}
        for cls in reversed(self.__class__.__mro__):
            hints.update(getattr(cls, "__annotations__", {}))
        for k in self.__dict__.keys():
            if not k.startswith("_"):
                hints[k] = Any

        for name in hints.keys():
            val = getattr(self, name, None)
            if isinstance(val, BaseModel):
                out[name] = val.model_dump()
            elif isinstance(val, list):
                out[name] = [item.model_dump() if isinstance(item, BaseModel) else item for item in val]
            elif isinstance(val, datetime):
                out[name] = val.isoformat()
            else:
                out[name] = val
        return out

    def dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def model_validate(cls, obj: Any) -> "BaseModel":
        if isinstance(obj, dict):
            return cls(**obj)
        # From SQLAlchemy or object attributes
        kwargs = {}
        hints = {}
        for c in reversed(cls.__mro__):
            hints.update(getattr(c, "__annotations__", {}))
        for name in hints.keys():
            if hasattr(obj, name):
                val = getattr(obj, name)
                kwargs[name] = val
        return cls(**kwargs)

    @classmethod
    def from_orm(cls, obj: Any) -> "BaseModel":
        return cls.model_validate(obj)
