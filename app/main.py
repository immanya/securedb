import logging
from contextlib import asynccontextmanager
from app.compat import FastAPI, CORSMiddleware
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import User, TargetDatabase, Backup, BackupSchedule, AuditLog, SecurityAlert
from app.api.routes_auth import router as auth_router
from app.api.routes_databases import router as databases_router
from app.api.routes_backups import router as backups_router
from app.api.routes_schedules import router as schedules_router
from app.api.routes_logs import router as logs_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_dashboard import router as dashboard_router
from app.services.scheduler_service import init_scheduler, shutdown_scheduler
from app.core.crypto import encrypt_credential

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securedb")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables
    logger.info("Initializing SecureDB schema...")
    Base.metadata.create_all(bind=engine)
    
    # Seed default sample CollegeDB target if none exists
    db = SessionLocal()
    try:
        sample_db = db.query(TargetDatabase).filter(TargetDatabase.name == "CollegeDB").first()
        if not sample_db:
            sample_db = TargetDatabase(
                name="CollegeDB",
                host="localhost",
                port=5432,
                username="postgres",
                encrypted_password=encrypt_credential("collegedb_secure_pass"),
                database_name="collegedb",
                db_type="postgresql",
                is_active=True
            )
            db.add(sample_db)
            db.commit()
            logger.info("Sample TargetDatabase 'CollegeDB' provisioned.")
    finally:
        db.close()
        
    # Start APScheduler
    logger.info("Starting background backup scheduler...")
    init_scheduler()
    
    yield
    
    # Shutdown scheduler
    logger.info("Stopping background backup scheduler...")
    shutdown_scheduler()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="SecureDB: Web-based automated database backup and cryptographic security management system",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(auth_router, prefix="/api")
app.include_router(databases_router, prefix="/api")
app.include_router(backups_router, prefix="/api")
app.include_router(schedules_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecureDB",
        "version": settings.PROJECT_VERSION
    }

# Mount built React frontend static files if available
import os
from starlette.staticfiles import StaticFiles
frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="static")

