from fastapi import FastAPI, Depends, HTTPException, status, Cookie, Response, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from redis_client import redis_client
from auth import get_current_user, RequireRole
import secrets
from passlib.context import CryptContext
from database import engine, get_db
from models import User, Base, AuditLog, RoleEnum, Case, Evidence, TimelineEvent, CaseCategory, CasePriority, EvidenceTag, AutopsyReport, InjuryRecord, CaseStatus
from schemas import TimelineEventResponse, CreateCaseRequest, SetPasswordRequest, LoginRequest, ProvisionRequest, DashboardStatsResponse, AutopsyReportCreate, InjuryCreate, RecentCaseRow
import shutil
import os
from typing import List
from sqlalchemy import cast, Date
from datetime import date
# This line tells SQLAlchemy to look at all your models and create the 
# actual SQL tables in your PostgreSQL database if they don't already exist.
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Allow the Vite dev server to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define your access groups
allow_admin = RequireRole([RoleEnum.ADMIN])
allow_doctors = RequireRole([RoleEnum.FORENSIC_DOCTOR, RoleEnum.LAB_TECH])
allow_evidence_handlers = RequireRole([RoleEnum.POLICE_INVESTIGATOR, RoleEnum.LAB_TECH])

# 1. Security & Connections Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



# 3. The API Endpoint
@app.post("/api/admin/provision-user", dependencies=[Depends(allow_admin)])
def provision_user(request: ProvisionRequest, db: Session = Depends(get_db)):
    
    # Step A: Verify the Admin (Strict Access Control)
    admin = db.query(User).filter(User.id == request.admin_id, User.role == RoleEnum.ADMIN).first()
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized: Only Admins can provision credentials.")

    # Step B: Ensure the user exists in Postgres
    user = db.query(User).filter(User.badge_number == request.badge_number).first()
    if not user:
        # If they don't exist, create their permanent record
        user = User(badge_number=request.badge_number, role=request.role)
        db.add(user)
        db.flush() # Gets the new user ID without fully committing the transaction yet

    # Step C: Generate the secure One-Time Password
    # secrets.token_urlsafe is cryptographically secure, unlike standard random modules
    plain_otp = secrets.token_urlsafe(9) 
    hashed_otp = pwd_context.hash(plain_otp)

    # Step D: Store in Redis with a 24-hour TTL (86400 seconds)!
    redis_key = f"otp:{request.badge_number}"
    redis_client.setex(name=redis_key, time=86400, value=hashed_otp)

    # Step E: Write the Immutable Audit Log
    audit_log = AuditLog(
        actor_id=admin.id,
        action=f"Provisioned one-time credential for badge {request.badge_number}",
        ip_address="127.0.0.1" # In production, you grab this from the FastAPI request headers
    )
    db.add(audit_log)
    
    # Step F: Save everything to PostgreSQL
    db.commit()

    # Step G: Return the plain text OTP *once* to the Admin
    return {
        "message": "User provisioned successfully",
        "badge_number": request.badge_number,
        "temporary_password": plain_otp,
        "expires_in": "24 hours"
    }


@app.post("/api/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.badge_number == request.badge_number).first()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    # PATH A: First-Time Login (Checking Redis)
    if user.requires_password_reset:
        redis_key = f"otp:{request.badge_number}"
        hashed_otp = redis_client.get(redis_key)
        
        # Burn after reading
        if hashed_otp:
            redis_client.delete(redis_key)
            
        if not hashed_otp or not pwd_context.verify(request.password, hashed_otp):
            raise HTTPException(status_code=401, detail="Invalid or expired temporary credential.")
            
        # We issue a temporary, restricted token just for setting the password.
        setup_token = secrets.token_hex(32) 
        
        # Store in Redis for 1 hour (3600 seconds) so we can verify it in Step 3
        redis_client.setex(f"setup:{user.badge_number}", 3600, setup_token)
        
        content = {
            "status": "requires_reset",
            "message": "Temporary login successful. Must set permanent password."
        }
        res = JSONResponse(content=content)
        res.set_cookie(key="setup_token", value=setup_token, httponly=True, max_age=3600)
        return res

    # PATH B: Regular Login (Checking Postgres)
    else:
        if not user.password_hash or not pwd_context.verify(request.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials.")
            
        # Success! Issue the real session token.
        access_token = secrets.token_hex(32)

        redis_client.setex(f"session:{access_token}", 86400, user.id)

        return {
            "status": "success",
            "access_token": access_token,
            "role": user.role.value
        }

#Setting up the password after login success.
@app.post("/api/auth/set-password")
def set_permanent_password(request: SetPasswordRequest, response: Response, setup_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.badge_number == request.badge_number).first()
    
    #Checking if the user exists and requires a password reset
    if not user or not user.requires_password_reset:
        raise HTTPException(status_code=400, detail="User does not require a password reset.")

    if not setup_token or not redis_client.get(f"setup:{request.badge_number}") or redis_client.get(f"setup:{request.badge_number}") != setup_token:
        raise HTTPException(status_code=400, detail="Invalid or missing setup token cookie.")

    # 1. Hash the new permanent password
    user.password_hash = pwd_context.hash(request.new_password)
    
    # 2. Flip the state machine flag so they can never use this endpoint again
    user.requires_password_reset = False 
    
    # 3. Log the action
    audit_log = AuditLog(
        actor_id=user.id,
        action="User set permanent password",
        ip_address="127.0.0.1"
    )
    
    db.add(audit_log)
    db.commit()

    # 4. Issue the REAL access token so they are fully logged in
    access_token = secrets.token_hex(32)
    
    response.delete_cookie("setup_token")
    return {
        "message": "Password set successfully.",
        "access_token": access_token,
        "role": user.role.value
    }


# --- CASE MANAGEMENT ENPOINTS ---
@app.post("/api/cases",dependencies=[Depends(allow_evidence_handlers)])
def create_case(request: CreateCaseRequest, db: Session = Depends(get_db)):
    # Ensure the user assigned to this case actually exists
    user = db.query(User).filter(User.id == request.assigned_to_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Assigned user not found.")
    
    new_case = Case(
        case_number=request.case_number,
        category=request.category,
        victim=request.victim,
        location=request.location,
        priority=request.priority,
        assigned_to_id=request.assigned_to_id
    )
    
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    
    return {
        "message": "Case created successfully", 
        "case_id": new_case.id,
        "case_number": new_case.case_number
    }

# Create a directory to hold the files locally while you develop
os.makedirs("evidence_storage", exist_ok=True)

@app.post("/api/evidence/upload", dependencies=[Depends(allow_evidence_handlers)])
def upload_evidence(
    # When dealing with files, we use Form() instead of a Pydantic BaseModel
    case_id: int = Form(...),
    uploader_id: int = Form(...),
    tag: EvidenceTag = Form(...),
    title: str = Form(...),
    description: str | None = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # 1. Validate the Case exists
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # 2. Securely save the file to the local 'evidence_storage' folder
    safe_filename = f"case_{case_id}_{file.filename}"
    file_location = f"evidence_storage/{safe_filename}"
    
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer) 
        #Reads the file in small, manageable chunks unlike buffer.read() which reads the entire file into memory at once.

    # 3. Write the database record
    new_evidence = Evidence(
        case_id=case_id,
        uploader_id=uploader_id,
        tag=tag,        
        title=title,
        description=description,
        file_path=file_location # We save the path, not the file!
    )
    
    db.add(new_evidence)
    
    # Whenever evidence is uploaded, everyone on the case should see it on the timeline.
    timeline_update = TimelineEvent(
        case_id=case_id,
        author_id=uploader_id,
        event_category="EVIDENCE_UPLOADED",
        description=f"Uploaded new {tag.value} evidence: {title}"
    )
    db.add(timeline_update)
    
    db.commit()

    return {
        "message": "Evidence uploaded successfully",
        "file_name": file.filename,
        "tag": tag.value
    }

@app.post("/api/autopsy/submit", dependencies=[Depends(allow_doctors)])
def submit_autopsy_report(report: AutopsyReportCreate, db: Session = Depends(get_db)):
    
    # Step A: Verify the Case exists and is OPEN
    case = db.query(Case).filter(Case.id == report.case_id).first()
    # 1. Check if the case exists
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")  
    
    # 2. Check if the case is actually open
    if case.status == CaseStatus.CLOSED:
        raise HTTPException(status_code=400, detail="Cannot submit an autopsy report for a closed case.")

    # 3. Check if the doctor exists
    doctor = db.query(User).filter(User.id == report.doctor_id).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found.")

    # Step B: Create the Parent Autopsy Report
    new_autopsy = AutopsyReport(
        case_id=report.case_id,
        doctor_id=report.doctor_id,
        general_notes=report.general_notes
    )
    
    db.add(new_autopsy)
    db.flush() # This is critical! It assigns an ID to 'new_autopsy' without committing yet.

    # Step C: Loop through the JSON array and create the Child Injury Records
    injury_objects = []
    for injury_data in report.injuries:
        new_injury = InjuryRecord(
            autopsy_id=new_autopsy.id, # We tie it to the parent ID we just generated
            body_part=injury_data.body_part,
            injury_type=injury_data.injury_type,
            depth=injury_data.depth,
            severity=injury_data.severity,
            length_cm=injury_data.length_cm,
            width_cm=injury_data.width_cm,
            specific_notes=injury_data.specific_notes
        )
        injury_objects.append(new_injury)
        
    # Bulk insert all the injuries at once for high performance
    db.add_all(injury_objects)

    # Step D: Update the Timeline 
    timeline_update = TimelineEvent(
        case_id=report.case_id,
        author_id=report.doctor_id,
        event_category="AUTOPSY_COMPLETED",
        description=f"Forensic Autopsy submitted logging {len(injury_objects)} distinct injuries."
    )
    db.add(timeline_update)

    # Step E: The Atomic Commit
    # If any part of the above failed, none of it saves. If we reach here, it all saves.
    db.commit()

    return {
        "message": "Autopsy report and injuries successfully recorded.",
        "autopsy_id": new_autopsy.id,
        "total_injuries_logged": len(injury_objects)
    }

@app.get("/api/cases/{case_id}/timeline", response_model=List[TimelineEventResponse],dependencies=[Depends(get_current_user)])
def get_case_timeline(case_id: int, db: Session = Depends(get_db)):
    
    # Step A: Verify the case actually exists
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    # Step B: Fetch the ledger of events
    # We query the TimelineEvent table, filter by the specific case, 
    # and critically, we order them by timestamp descending (newest first).
    events = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp.desc())
        .all()
    )

    # FastAPI and Pydantic will automatically convert these SQLAlchemy objects 
    # into a clean JSON array because of the `response_model` we defined above.
    return events

@app.get("/api/dashboard/stats", response_model=DashboardStatsResponse, dependencies=[Depends(get_current_user)])
def get_dashboard_stats(db: Session = Depends(get_db)):
    
    # 1. Active Cases (Status is NOT Closed)
    active_cases = db.query(Case).filter(Case.status != CaseStatus.CLOSED).count()

    # 2. Pending Reports (Autopsy Reports that exist but are not "Finalized")
    # We assume a report is pending if it exists but has no 'finalized_date'.
    pending_reports = db.query(AutopsyReport).filter(AutopsyReport.finalized_date.is_(None)).count()

    # 3. Today's Autopsies (Reports finalized today)
    today = date.today()
    todays_autopsies = db.query(AutopsyReport).filter(
        AutopsyReport.finalized_date.cast(Date) == today
    ).count()

    # 4. Court Hearings (Cases with a hearing scheduled for today)
    court_hearings = db.query(Case).filter(
        Case.court_hearing_date.cast(Date) == today
    ).count()

    # 5. Recent Cases (The Mini-Table Data)
    # We fetch the latest 5 cases that are not drafts
    recent_cases = (
        db.query(Case)
        .filter(Case.status != CaseStatus.DRAFT)
        .order_by(Case.created_at.desc())
        .limit(5)
        .all()
    )

    # Convert the SQLAlchemy models to Pydantic Response Models
    recent_cases_list = [
        RecentCaseRow(
            id=c.id,
            case_number=c.case_number,
            title=c.title,
            status=c.status.value, # Convert Enum to String
            created_at=c.created_at
        )
        for c in recent_cases
    ]

    return DashboardStatsResponse(
        active_cases=active_cases,
        pending_reports=pending_reports,
        todays_autopsies=todays_autopsies,
        court_hearings=court_hearings,
        recent_cases=recent_cases_list
    )


# --- READ ENDPOINTS FOR FRONTEND ---

@app.get("/api/cases", dependencies=[Depends(get_current_user)])
def get_cases(db: Session = Depends(get_db)):
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    return [
        {
            "id": c.id,
            "case_number": c.case_number,
            "category": c.category.value,
            "victim": c.victim,
            "location": c.location,
            "status": c.status.value,
            "priority": c.priority.value,
            "assigned_to_id": c.assigned_to_id,
            "created_at": c.created_at,
        }
        for c in cases
    ]


@app.get("/api/cases/{case_id}", dependencies=[Depends(get_current_user)])
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {
        "id": case.id,
        "case_number": case.case_number,
        "category": case.category.value,
        "victim": case.victim,
        "location": case.location,
        "status": case.status.value,
        "priority": case.priority.value,
        "assigned_to_id": case.assigned_to_id,
        "created_at": case.created_at,
    }


@app.get("/api/evidence/{case_id}", dependencies=[Depends(get_current_user)])
def get_evidence(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    items = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.uploaded_at.desc()).all()
    return [
        {
            "id": e.id,
            "case_id": e.case_id,
            "uploader_id": e.uploader_id,
            "tag": e.tag.value,
            "title": e.title,
            "description": e.description,
            "file_path": e.file_path,
            "uploaded_at": e.uploaded_at,
        }
        for e in items
    ]


@app.get("/api/users/me", dependencies=[Depends(get_current_user)])
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "badge_number": current_user.badge_number,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
    }
