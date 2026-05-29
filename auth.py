from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from typing import List
from models import RoleEnum, User
from sqlalchemy.orm import Session
from database import get_db
from redis_client import redis_client
# This tells FastAPI to look for a "Bearer" token in the request headers
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user_id = redis_client.get(f"session:{token}")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user

class RequireRole:
    def __init__(self, allowed_roles: List[RoleEnum]):
        self.allowed_roles = allowed_roles

    # The __call__ method allows instances of this class to act like functions,
    # which is exactly what FastAPI Needs for dependencies.
    def __call__(self, current_user: User = Depends(get_current_user)):
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Role {current_user.role.value} is not authorized for this action."
            )
        return current_user