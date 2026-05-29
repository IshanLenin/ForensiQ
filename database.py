from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Format: postgresql://<user>:<password>@<host>:<port>/<database_name>
SQLALCHEMY_DATABASE_URL = "postgresql://admin:securepassword123@127.0.0.1:5433/forensics_app"

# The engine is the core interface to the database. 
# It handles the underlying connection pool to Postgres.
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# SessionLocal is a factory that creates new database sessions.
# autocommit=False ensures we manually commit transactions (like we did in main.py)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# This is the dependency we inject into our FastAPI endpoints
def get_db():
    db = SessionLocal()
    try:
        # 'yield' hands the session to the endpoint. 
        # When the endpoint finishes, the code resumes here.
        yield db
    finally:
        # This ensures the connection is always returned to the pool, 
        # even if your endpoint crashes or throws an exception.
        db.close()