from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from models import BodyPart, InjuryType, InjuryDepth, InjurySeverity, AutopsyReport, CaseCategory, CasePriority, CaseStatus, RoleEnum

# 1. The Child Schema (Validates a single injury)
class InjuryCreate(BaseModel):
    body_part: BodyPart
    injury_type: InjuryType
    depth: InjuryDepth
    severity: InjurySeverity
    length_cm: float
    width_cm: float
    specific_notes: Optional[str] = None

# 2. The Parent Schema (Validates the whole report + the list of injuries)
class AutopsyReportCreate(BaseModel):
    case_id: int
    doctor_id: int
    general_notes: Optional[str] = None
    
    # This single line tells FastAPI to expect a JSON array of the injuries above!
    injuries: List[InjuryCreate]

class TimelineEventResponse(BaseModel):
    id: int
    case_id: int
    author_id: int
    event_category: str
    description: str
    timestamp: datetime

    # In Pydantic v2 (which modern FastAPI uses), this tells Pydantic to 
    # read the data directly from the SQLAlchemy database models.
    class Config:
        from_attributes = True
    
class CreateCaseRequest(BaseModel):
    case_number: str
    status: CaseStatus = CaseStatus.DRAFT
    category: CaseCategory
    victim: str = "Unknown" 
    location: str | None = None
    priority: CasePriority = CasePriority.MEDIUM
    assigned_to_id: int

#Once the temporary login is successful, the user must reset their password.
class SetPasswordRequest(BaseModel):
    badge_number: str
    new_password: str

#For the initial login
class LoginRequest(BaseModel):
    badge_number: str
    password: str

# 2. Define the expected incoming JSON from your Figma frontend
class ProvisionRequest(BaseModel):
    badge_number: str
    role: RoleEnum
    admin_id: int # In a real app, this is extracted securely from the Admin's login token


# 1. The Mini-Table Row Schema
class RecentCaseRow(BaseModel):
    id: int
    case_number: str
    title: str
    status: str # Convert the Enum to a string for the frontend
    created_at: datetime

    class Config:
        from_attributes = True

# 2. The Overall Dashboard Schema
class DashboardStatsResponse(BaseModel):
    active_cases: int
    pending_reports: int
    todays_autopsies: int
    court_hearings: int
    recent_cases: List[RecentCaseRow]