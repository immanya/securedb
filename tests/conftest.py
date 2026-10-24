import os
import pytest
from app.compat import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECUREDB_MASTER_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

from app.database import Base, get_db
import app.models  # Ensure all models are registered with Base.metadata
from app.main import app
from app.models.user import User
from app.models.target_db import TargetDatabase
from app.core.password import hash_password
from app.core.crypto import encrypt_credential

# Setup in-memory test DB
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture
def db_session():
    """Provides a transactional database session for tests."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def client(db_session):
    """FastAPI TestClient overriding get_db with test session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture
def sample_users(db_session):
    """Provisions admin, manager, and viewer test accounts."""
    admin = User(
        username="admin_user",
        hashed_password=hash_password("AdminPass123!"),
        role="admin"
    )
    manager = User(
        username="manager_user",
        hashed_password=hash_password("ManagerPass123!"),
        role="manager"
    )
    viewer = User(
        username="viewer_user",
        hashed_password=hash_password("ViewerPass123!"),
        role="viewer"
    )
    db_session.add_all([admin, manager, viewer])
    db_session.commit()
    return {"admin": admin, "manager": manager, "viewer": viewer}

@pytest.fixture
def sample_target_db(db_session):
    """Provisions a sample target database record."""
    target = TargetDatabase(
        name="TestCollegeDB",
        host="localhost",
        port=5432,
        username="postgres",
        encrypted_password=encrypt_credential("secret_db_pass"),
        database_name="collegedb",
        db_type="postgresql",
        is_active=True
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target
