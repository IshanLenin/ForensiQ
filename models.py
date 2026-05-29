from sqlalchemy import Column, Integer, String, Boolean, Enum, DateTime, ForeignKey,Float   
from sqlalchemy.orm import declarative_base,relationship
from datetime import datetime
import enum

# This is the base class all our models will inherit from
Base = declarative_base()

# 1. Define the strict roles allowed in the system
class RoleEnum(enum.Enum):
    ADMIN = "ADMIN"
    FORENSIC_DOCTOR = "FORENSIC_DOCTOR"
    LAB_TECH = "LAB_TECH"
    POLICE_INVESTIGATOR = "POLICE_INVESTIGATOR"
    LEGAL_COURT = "LEGAL_COURT"

class CaseCategory(enum.Enum):
    HOMICIDE = "HOMICIDE"
    SUSPICIOUS_DEATH = "SUSPICIOUS_DEATH"
    UNATTENDED_DEATH = "UNATTENDED_DEATH"
    ACCIDENTAL_DEATH = "ACCIDENTAL_DEATH"
    OTHER = "OTHER"

class CasePriority(enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class CaseStatus(enum.Enum):
    IN_PROGRESS = "IN PROGRESS"
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    IN_COURT = "IN COURT"
    CLOSED = "CLOSED"   
    DRAFT = "DRAFT"

# 2. The permanent User table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    badge_number = Column(String, unique=True, index=True, nullable=False)
    role = Column(Enum(RoleEnum), nullable=False)
    is_active = Column(Boolean, default=True)
    
    password_hash = Column(String, nullable=True) # Null until they set it themselves
    requires_password_reset = Column(Boolean, default=True) # True by default when Admin creates them

# 3. The tamper-proof Audit Log table
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    # This links the action to the specific Admin who performed it
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=False) 
    action = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)

class EvidenceTag(enum.Enum):
    KEY_EVIDENCE = "KEY_EVIDENCE"
    MEDICAL = "MEDICAL"
    LOCATION = "LOCATION"
    SURVEILLANCE = "SURVEILLANCE"
    LAB = "LAB"

class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    
    # Required case info
    case_number = Column(String, unique=True, index=True, nullable=False)
    category = Column(Enum(CaseCategory), nullable=False)
    victim = Column(String, nullable=True, default="Unknown")
    location = Column(String, nullable=True)
    status = Column(Enum(CaseStatus), default=CaseStatus.IN_PROGRESS)
    priority = Column(Enum(CasePriority), default=CasePriority.MEDIUM)
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    
    # We must strictly track who uploaded this evidence for the chain of custody
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    tag = Column(Enum(EvidenceTag), nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    # We store where the file lives, not the file itself
    file_path = Column(String, nullable=False) 
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    event_category = Column(String, nullable=False)
    description = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

# 1. Body Parts
class BodyPart(enum.Enum):
    HEAD = "HEAD"
    NECK = "NECK"
    SHOULDERS = "SHOULDERS"
    UPPER_ARMS = "UPPER_ARMS"
    FOREARMS = "FOREARMS"
    HANDS = "HANDS"
    CHEST = "CHEST"
    ABDOMEN = "ABDOMEN"
    PELVIS = "PELVIS"
    THIGHS = "THIGHS"
    KNEES = "KNEES"
    LOWER_LEGS = "LOWER_LEGS"
    FOOT = "FOOT"
    BACK = "BACK"

# 2. Injury Types
class InjuryType(enum.Enum):
    LACERATION = "LACERATION"
    CONTUSION = "CONTUSION"
    ABRASION = "ABRASION"
    PUNCTURE = "PUNCTURE"
    LIGATURE_MARK = "LIGATURE_MARK"
    BURN = "BURN"
    FRACTURE = "FRACTURE"
    BITE_MARK = "BITE_MARK"
    GUNSHOT_WOUND = "GUNSHOT_WOUND"

# 3. Injury Depths
class InjuryDepth(enum.Enum):
    EPIDERMIS = "EPIDERMIS"
    DERMIS = "DERMIS"
    SUPERFICIAL = "SUPERFICIAL"
    SUBCUTANEOUS = "SUBCUTANEOUS"
    MUSCLE = "MUSCLE"
    BONE = "BONE"

# 4. Injury Severities
class InjurySeverity(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

# The Parent: The Overall Autopsy Report
class AutopsyReport(Base):
    __tablename__ = "autopsy_reports"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), unique=True, nullable=False)
    
    # Strictly tie this report to the doctor who authored it
    doctor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    date_of_examination = Column(DateTime, default=datetime.utcnow)
    general_notes = Column(String, nullable=True) # For overarching summaries
    
    # This relationship allows SQLAlchemy to easily fetch all injuries tied to this report
    injuries = relationship("InjuryRecord", back_populates="autopsy_report")

# The Child: The Individual Injuries
class InjuryRecord(Base):
    __tablename__ = "injury_records"

    id = Column(Integer, primary_key=True, index=True)
    autopsy_id = Column(Integer, ForeignKey("autopsy_reports.id"), nullable=False)
    
    # The strictly enforced Enums
    body_part = Column(Enum(BodyPart), nullable=False)
    injury_type = Column(Enum(InjuryType), nullable=False)
    depth = Column(Enum(InjuryDepth), nullable=False)
    severity = Column(Enum(InjurySeverity), nullable=False)
    
    # Dimensions (Stored as floats so you can do math/sorting on them later if needed)
    length_cm = Column(Float, nullable=False)
    width_cm = Column(Float, nullable=False)
    
    # Optional specific notes for this exact injury
    specific_notes = Column(String, nullable=True)

    # Links back to the parent report
    autopsy_report = relationship("AutopsyReport", back_populates="injuries")