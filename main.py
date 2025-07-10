from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Depends, UploadFile, File, Form, Request
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse
from fastapi.responses import StreamingResponse
import io
import csv
from sqlalchemy.orm import joinedload
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
from datetime import date, datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
import hashlib
import secrets
import os
import jwt
import requests
import json
import uuid
from threading import Thread
from openai import OpenAI
from dotenv import load_dotenv
from PIL import Image
import base64
import pandas as pd

# Database imports
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer, ForeignKey, Date, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# Load environment variables from .env file
load_dotenv()

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./medical_app.db")
# Increase timeout for SQLite and enable WAL mode
if "sqlite" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 30}
    )
    # Enable WAL mode
    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.close()
else:
    engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Directory for uploaded images
IMAGE_DIR = os.path.join(os.getcwd(), "uploaded_images")
if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

def utc_now():
    """Returns current UTC datetime with timezone info."""
    return datetime.now(timezone.utc)

# Database Models (Updated Schema)
class User(Base):
    """SQLAlchemy model for user accounts."""
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    first_name = Column(String, nullable=False)
    middle_name = Column(String, nullable=True)
    last_name = Column(String, nullable=False)
    date_of_birth = Column(Date, nullable=False)
    password_hash = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    password_updated_at = Column(DateTime, nullable=True)
    
    medical_sessions = relationship("MedicalSession", back_populates="user", cascade="all, delete-orphan")
    chat_sessions = relationship("ChatSession", back_populates="user", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", back_populates="user", cascade="all, delete-orphan")

class MedicalSession(Base):
    """SQLAlchemy model for medical assessment sessions."""
    __tablename__ = "medical_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    image_path = Column(String, nullable=False)
    status = Column(String, default="questioning")
    current_question_index = Column(Integer, default=0)
    treatment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = relationship("User", back_populates="medical_sessions")
    questions = relationship("MedicalQuestion", back_populates="session", cascade="all, delete-orphan")
    qa_history = relationship("MedicalQA", back_populates="session", cascade="all, delete-orphan")

class MedicalQuestion(Base):
    """SQLAlchemy model for questions within a medical assessment session."""
    __tablename__ = "medical_questions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("medical_sessions.id"), nullable=False)
    question_text = Column(Text, nullable=False)
    question_type = Column(String, nullable=False)
    options = Column(Text, nullable=True)
    order_index = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    session = relationship("MedicalSession", back_populates="questions")

class MedicalQA(Base):
    """SQLAlchemy model for question-answer history within a medical assessment session."""
    __tablename__ = "medical_qa_history"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("medical_sessions.id"), nullable=False)
    question_id = Column(String, nullable=False)
    question_text = Column(Text, nullable=False)
    answer = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    session = relationship("MedicalSession", back_populates="qa_history")

class PendingVerification(Base):
    """SQLAlchemy model for pending email verifications."""
    __tablename__ = "pending_verifications"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    verification_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)  # This will be timezone-aware when created
    user_data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow) 


class PasswordResetToken(Base):
    """SQLAlchemy model for password reset tokens."""
    __tablename__ = "password_reset_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, index=True, nullable=False)
    reset_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)  # This will be timezone-aware when created
    created_at = Column(DateTime, default=datetime.utcnow) 

class ChatSession(Base):
    """SQLAlchemy model for chat sessions."""
    __tablename__ = "chat_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships with explicit cascade
    user = relationship("User", back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan", passive_deletes=True)

class ChatMessage(Base):
    """SQLAlchemy model for individual chat messages."""
    __tablename__ = "chat_messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    content = Column(Text, nullable=False)
    is_user = Column(Boolean, nullable=False)
    image_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    session = relationship("ChatSession", back_populates="messages")
    user = relationship("User", back_populates="chat_messages")

# Create database tables
Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    """Dependency to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Complete Medical & Authentication API", version="3.0.0")

# Mount static files directory for uploaded images
app.mount("/images", StaticFiles(directory=IMAGE_DIR), name="images")

# CORS middleware must be added to the main app before any routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable not set. Please set it for security.")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security scheme for JWT authentication
security = HTTPBearer()

# Email configuration with SendGrid
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("EMAIL_ADDRESS", "noreply@athlix.fit")

# OpenAI client initialization
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Pydantic models for Authentication
class UserSignup(BaseModel):
    """Request model for user signup."""
    email: EmailStr
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    date_of_birth: date
    password: str
     
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        if len(v.strip()) < 2:
            raise ValueError('Name must be at least 2 characters long')
        return v.strip().title()
    
    @validator('middle_name')
    def validate_middle_name(cls, v):
        if v is not None:
            if not v.strip():
                return None
            return v.strip().title()
        return v
    
    @validator('date_of_birth')
    def validate_age(cls, v):
        today = date.today()
        age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
        if age < 13:
            raise ValueError('Must be at least 13 years old')
        if age > 120:
            raise ValueError('Invalid date of birth: age exceeds 120 years.')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class EmailVerification(BaseModel):
    """Request model for email verification."""
    email: EmailStr
    verification_code: str

class UserSignIn(BaseModel):
    """Request model for user sign-in."""
    email: EmailStr
    password: str

class ForgotPassword(BaseModel):
    """Request model for initiating forgot password flow."""
    email: EmailStr

class ResetPassword(BaseModel):
    """Request model for resetting password with a code."""
    email: EmailStr
    reset_code: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class SignInResponse(BaseModel):
    """Response model for successful user sign-in."""
    access_token: str
    token_type: str
    expires_in: int
    user: dict

class UserResponse(BaseModel):
    """Response model for user data."""
    id: str
    email: str
    first_name: str
    middle_name: Optional[str]
    last_name: str
    date_of_birth: date
    created_at: datetime
    is_verified: bool
    message: str

# Pydantic models for Chat System
class ChatMessagePayload(BaseModel):
    """Request model for sending a chat message."""
    message: str
    session_id: Optional[str] = None

class ChatResponseModel(BaseModel):
    """Response model for a chat message from AI."""
    response: str
    session_id: str
    message_id: str
    timestamp: datetime

class QuestionResponse(BaseModel):
    session_id: str
    question_id: str
    answer: str

class SessionStatus(BaseModel):
    session_id: str
    status: str
    questions: List[Dict] = []
    current_question_index: int = 0
    treatment: Optional[str] = None

class TreatmentResponse(BaseModel):
    session_id: str
    treatment: str
    session_complete: bool

class CreateChatSessionRequest(BaseModel):
    """Request model for creating a new chat session."""
    title: Optional[str] = None

# Authentication Helper Functions
def hash_password(password: str) -> str:
    """Hashes a password using SHA-256 with a random salt."""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"

def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against a stored hash."""
    try:
        salt, pwd_hash = hashed_password.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except ValueError:
        return False

def create_jwt_token(user_data: dict) -> str:
    """Creates a JWT token for the given user data."""
    try:
        payload = {
            "user_id": user_data["id"],
            "email": user_data["email"],
            "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
            "iat": datetime.now(timezone.utc)
        }
        
        # Try different approaches based on your JWT library
        try:
            # For PyJWT version 2.x+
            return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        except AttributeError:
            # For older PyJWT versions
            import PyJWT
            return PyJWT.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        except:
            # Fallback using python-jose
            from jose import jwt as jose_jwt
            return jose_jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            
    except Exception as e:
        print(f"JWT encoding error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating authentication token"
        )

def verify_jwt_token(token: str) -> dict:
    """Verifies and decodes a JWT token."""
    try:
        # Try different approaches based on your JWT library
        try:
            # For PyJWT version 2.x+
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        except AttributeError:
            # For older PyJWT versions
            import PyJWT
            payload = PyJWT.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        except:
            # Fallback using python-jose
            from jose import jwt as jose_jwt
            payload = jose_jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    except Exception as e:
        print(f"JWT decoding error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """
    Dependency to get the current authenticated user from the JWT token.
    """
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials: User ID missing from token."
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or token invalid."
        )
    
    return user

def generate_user_id() -> str:
    """Generates a unique URL-safe user ID."""
    return secrets.token_urlsafe(16)

def generate_verification_code() -> str:
    """Generates a 6-digit numeric verification code."""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def generate_reset_token() -> str:
    """Generates a 6-digit numeric OTP for password reset."""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

# Medical System Helper Functions
def encode_image_from_upload(upload_file: UploadFile) -> str:
    try:
        image_content = upload_file.file.read()
        img = Image.open(io.BytesIO(image_content))
        img.verify()
        return base64.b64encode(image_content).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image file format.")

def get_initial_questions_from_image(base64_image: str) -> List[Dict]:
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are a medical assessment AI. Analyze the provided image and generate important questions.\n                    Return a JSON object:\n                    {\n                        "questions": [\n                            {"id": "q1", "question": "Your question", "type": "text|multiple_choice|number", "options": ["option1", "option2"]}\n                        ]\n                    }\n                    Generate 3-5 relevant questions."""
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyze this image and provide questions."},
                        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}}
                    ]
                }
            ],
            max_tokens=1000,
            response_format={"type": "json_object"}
        )
        questions_data = json.loads(response.choices[0].message.content)
        return questions_data.get("questions", [])
    except Exception:
        return [
            {"id": str(uuid.uuid4()), "question": "Describe the primary issue or symptom.", "type": "text"},
            {"id": str(uuid.uuid4()), "question": "When did you first notice this issue?", "type": "text"},
            {"id": str(uuid.uuid4()), "question": "Rate any pain (1-10).", "type": "number"}
        ]

def generate_treatment_or_more_questions(session_data: Dict, db: Session) -> Dict:
    try:
        conversation_context = "User has uploaded an image.\n\nHere is the Q&A history:\n"
        qa_history = db.query(MedicalQA).filter(MedicalQA.session_id == session_data["session_id"]).order_by(MedicalQA.created_at).all()
        for qa in qa_history:
            conversation_context += f"Q: {qa.question_text}\nA: {qa.answer}\n\n"
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are a trainer and injury expert. Based on the history, decide if you can provide recommendations or need more questions.\n                    Return JSON:\n                    1. {\"need_more_info\": true, \"questions\": [{\"id\": \"q1\", \"question\": \"...\", \"type\": \"...\"}]}\n                    2. {\"need_more_info\": false, \"treatment\": \"...\"}"""
                },
                {"role": "user", "content": conversation_context}
            ],
            max_tokens=1500,
            response_format={"type": "json_object"}
        )
        parsed_response = json.loads(response.choices[0].message.content)
        if parsed_response["need_more_info"]:
            for q in parsed_response["questions"]:
                if "id" not in q or not q["id"]:
                    q["id"] = str(uuid.uuid4())
        return parsed_response
    except Exception:
        return {"need_more_info": false, "treatment": "Consult a professional."}

# Email Functions

def send_verification_email(email: str, verification_code: str, first_name: str):
    """Send verification email using Mailjet API."""
    
    mailjet_api_key = os.getenv("MAILJET_API_KEY")
    mailjet_secret_key = os.getenv("MAILJET_SECRET_KEY")
    
    url = "https://api.mailjet.com/v3.1/send"
    
    payload = {
        "Messages": [
            {
                "From": {
                    "Email": "noreply@athlix.fit",
                    "Name": "Athlix"
                },
                "To": [
                    {
                        "Email": email,
                        "Name": first_name
                    }
                ],
                "Subject": "Athlix - Verify Your Account",
                "TextPart": f"""
Hi {first_name},

Welcome to Athlix!

Your verification code is: {verification_code}

This code expires in 15 minutes.

Best regards,
The Athlix Team
                """,
                "HTMLPart": f"""
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background: #28a745; color: white; padding: 20px; text-align: center;">
        <h1>Athlix</h1>
        <p>Account Verification</p>
    </div>
    <div style="padding: 30px;">
        <h2>Hi {first_name}!</h2>
        <p>Welcome to Athlix! Please verify your email with this code:</p>
        <div style="background: #f0f8f0; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px;">
            <h1 style="color: #28a745; letter-spacing: 3px; margin: 0;">{verification_code}</h1>
        </div>
        <p><strong>This code expires in 15 minutes.</strong></p>
        <p>If you didn't sign up, please ignore this email.</p>
        <hr>
        <p>Best regards,<br>The Athlix Team</p>
    </div>
</body>
</html>
                """
            }
        ]
    }
    
    try:
        response = requests.post(
            url,
            auth=(mailjet_api_key, mailjet_secret_key),
            headers={'Content-Type': 'application/json'},
            data=json.dumps(payload),
            timeout=30
        )
        
        if response.status_code == 200:
            print(f"✅ Verification email sent successfully to {email} via Mailjet")
            result = response.json()
            print(f"Message ID: {result['Messages'][0]['To'][0]['MessageID']}")
        else:
            print(f"❌ Failed to send email. Status: {response.status_code}")
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"💥 Error sending email: {str(e)}")
        raise

def send_password_reset_email(email: str, reset_code: str, first_name: str):
    """Sends a password reset email to the user with an embedded logo using SendGrid."""
    mailjet_api_key = os.getenv("MAILJET_API_KEY")
    mailjet_secret_key = os.getenv("MAILJET_SECRET_KEY")
    
    payload = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": "Athlix Team"
                },
                "To": [
                    {
                        "Email": email,
                        "Name": first_name
                    }
                ],
                "Subject": "Athlix - Password Reset Code",
                "TextPart": f"""
Hi {first_name},

We received a request to reset your password for your Athlix account.

Your password reset code is: {reset_code}

This code will expire in 30 minutes.

If you didn't request a password reset, please ignore this email.

Best regards,
The Athlix Team
                """,
                "HTMLPart": f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #667eea; margin: 0;">Athlix</h1>
        <p style="color: #666; margin: 5px 0;">Password Reset Request</p>
    </div>
    
    <h2 style="color: #333;">Hi {first_name}!</h2>
    
    <p>We received a request to reset your password for your Athlix account.</p>
    
    <div style="background: #f8f9fa; border: 2px solid #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
        <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">Your Reset Code:</p>
        <h1 style="margin: 0; color: #667eea; font-size: 32px; letter-spacing: 3px; font-family: monospace;">{reset_code}</h1>
    </div>
    
    <p style="color: #e74c3c; font-weight: bold;">⏰ This code expires in 30 minutes.</p>
    
    <p>If you didn't request a password reset, please ignore this email. Your account remains secure.</p>
    
    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
    
    <p style="color: #666; font-size: 14px;">
        Best regards,<br>
        The Athlix Team
    </p>
</body>
</html>
                """
            }
        ]
    }
    
    try:
        response = requests.post(
            "https://api.mailjet.com/v3.1/send",
            auth=(mailjet_api_key, mailjet_secret_key),
            headers={'Content-Type': 'application/json'},
            data=json.dumps(payload),
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            message_id = result['Messages'][0]['To'][0]['MessageID']
            print(f"✅ Password reset email sent to {email} via Mailjet")
            print(f"📧 Message ID: {message_id}")
        else:
            print(f"❌ Mailjet error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Mailjet error: {str(e)}")

def send_email_background(email: str, verification_code: str, first_name: str):
    """Helper to send verification email in a background thread."""
    thread = Thread(target=send_verification_email, args=(email, verification_code, first_name))
    thread.start()

def send_reset_email_background(email: str, reset_code: str, first_name: str):
    """Helper to send password reset email in a background thread."""
    thread = Thread(target=send_password_reset_email, args=(email, reset_code, first_name))
    thread.start()

# AI Helper Functions
def analyze_image_and_generate_response(base64_image: str, user_message: str, user_data: User, session_id: str, db: Session) -> str:
    """
    Analyzes an uploaded image using OpenAI Vision and generates a medical response.
    Enhanced to include conversation context even for image analysis.
    """
    try:
        # Build system message with conversation awareness
        system_content = f"""You are a helpful medical AI assistant for {user_data.first_name}. 
        
        You can help with:
        - Medical image analysis (general observations, not diagnosis)
        - Health questions and concerns
        - Workout and fitness advice
        - Injury prevention tips
        - Wellness guidance
        - Basic medical information
        
        CONVERSATION CONTEXT:
        - This is part of an ongoing conversation with {user_data.first_name}
        - Reference any relevant previous discussions if the image relates to earlier topics
        - Build upon previous advice or observations when appropriate
        
        When analyzing images:
        - Describe what you observe in the image
        - Relate observations to any previous health discussions if relevant
        - Provide general health information relevant to what you see
        - Ask relevant follow-up questions to better understand the situation
        - Always recommend consulting healthcare professionals for proper diagnosis
        
        Always be supportive, informative, and friendly. Keep responses conversational and personalized."""
        
        # Get recent conversation context (last 10 messages for image analysis)
        recent_history = db.query(ChatMessage).filter(
            ChatMessage.session_id == session_id
        ).order_by(ChatMessage.created_at.desc()).limit(10).all()
        
        # Build context from recent messages
        context_summary = ""
        if recent_history:
            context_summary = "\n\nRecent conversation context:\n"
            for msg in reversed(recent_history):  # Reverse to chronological order
                role = "User" if msg.is_user else "AI"
                content = msg.content[:100] + "..." if len(msg.content) > 100 else msg.content
                if msg.image_path:
                    content = f"[Image] {content}"
                context_summary += f"{role}: {content}\n"
        
        # Create messages for vision API
        messages = [
            {
                "role": "system",
                "content": system_content + context_summary
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": user_message},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                    }
                ]
            }
        ]
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=800,
            temperature=0.7,
            presence_penalty=0.1,
            frequency_penalty=0.1
        )
        
        return response.choices[0].message.content
        
    except Exception:
        return [
            {"id": str(uuid.uuid4()), "question": "Describe the primary issue or symptom.", "type": "text"},
            {"id": str(uuid.uuid4()), "question": "When did you first notice this issue?", "type": "text"},
            {"id": str(uuid.uuid4()), "question": "Rate any pain (1-10).", "type": "number"}
        ]


def generate_chat_response(user_message: str, session_id: str, user_data: User, db: Session) -> str:
    """
    Generates an AI chat response based on user input and chat history.
    Enhanced to better maintain conversation context.
    """
    try:
        # Build conversation context with system message
        messages = [
            {
                "role": "system",
                "content": f"""You are a helpful medical AI assistant for {user_data.first_name}. 
                
                You can help with:
                - General health questions and medical information
                - Workout and fitness advice
                - Injury prevention tips
                - Wellness guidance
                - Analysis of medical images when provided
                - Follow-up questions based on previous conversations
                
                IMPORTANT CONTEXT RULES:
                - Remember and reference previous parts of this conversation when relevant
                - Build upon previous answers and discussions
                - If the user refers to something mentioned earlier, acknowledge it
                - Provide continuity in your responses based on the conversation flow
                - Ask clarifying questions that build on previous exchanges
                
                Always be supportive, informative, and friendly. Remind users to consult qualified healthcare professionals for serious or specific medical concerns.
                Keep responses conversational and personalized. Reference previous parts of the conversation when appropriate."""
            }
        ]
        
        # Get recent chat history from database (increased to 20 messages for better context)
        chat_history = db.query(ChatMessage).filter(
            ChatMessage.session_id == session_id
        ).order_by(ChatMessage.created_at.asc()).limit(20).all()  # Changed to ascending order
        
        # Add conversation history to context
        for msg in chat_history:
            if msg.image_path:
                # If message has an image, mention it in the context
                content = f"[Image shared] {msg.content}"
            else:
                content = msg.content
            
            # Add message with proper role
            messages.append({
                "role": "user" if msg.is_user else "assistant", 
                "content": content
            })
        
        # Add the current user message
        messages.append({"role": "user", "content": user_message})
        
        # Generate response with better parameters for conversation continuity
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=600,  # Increased for more detailed responses
            temperature=0.7,
            presence_penalty=0.1,  # Encourage new topics while maintaining context
            frequency_penalty=0.1  # Reduce repetition
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error generating chat response from AI: {str(e)}")
        return f"I'm sorry {user_data.first_name}, I'm having trouble responding right now. Please try again later."

def save_uploaded_image(file: UploadFile, session_id: str, message_id: str) -> str:
    """Saves an uploaded image to the designated image directory."""
    try:
        # Ensure the file pointer is at the beginning
        file.file.seek(0)
        
        # Validate file extension
        file_extension = file.filename.split('.')[-1].lower()
        if file_extension not in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']:
            raise HTTPException(status_code=400, detail=f"Invalid image file extension: {file_extension}")

        # Create a unique filename to avoid collisions
        image_filename = f"{session_id}_{message_id}.{file_extension}"
        image_path = os.path.join(IMAGE_DIR, image_filename)

        # Save the file
        with open(image_path, "wb") as f:
            f.write(file.file.read())

        return image_path
    except Exception as e:
        # Log the error for debugging
        print(f"Error saving uploaded image: {str(e)}")
        # Re-raise as an HTTPException to be handled by FastAPI
        raise HTTPException(status_code=500, detail="Could not save uploaded image.")

# --- API Endpoints ---

@app.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup_user(user_data: UserSignup, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Registers a new user and sends an email verification code.
    User account is created only after email verification.
    """
    # Check if email already exists as a verified user
    existing_user = db.query(User).filter(User.email == user_data.email.lower()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered and verified."
        )
    
    # Check if email has a pending verification
    pending = db.query(PendingVerification).filter(PendingVerification.email == user_data.email.lower()).first()
    if pending:
        # If there's an expired pending verification, delete it to allow new signup
        if datetime.now(timezone.utc) > pending.expires_at:
            db.delete(pending)
            db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already has a pending verification. Please check your email or use resend verification if the code expired."
            )
    
    # Optional: Restrict signup to Gmail addresses
    if not user_data.email.lower().endswith('@gmail.com'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only Gmail addresses are accepted for signup."
        )
    
    # Generate unique ID, verification code, and hash password
    user_id = generate_user_id()
    verification_code = generate_verification_code()
    hashed_password = hash_password(user_data.password)
    
    # Prepare user data to be stored temporarily
    user_record_temp = {
        "id": user_id,
        "email": user_data.email.lower(),
        "first_name": user_data.first_name,
        "middle_name": user_data.middle_name,
        "last_name": user_data.last_name,
        "date_of_birth": user_data.date_of_birth.isoformat(),
        "password_hash": hashed_password,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Store pending verification in database
    pending_verification = PendingVerification(
        email=user_data.email.lower(),
        verification_code=verification_code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        user_data=json.dumps(user_record_temp)
    )
    
    db.add(pending_verification)
    db.commit()
    
    # Send verification email in background
    background_tasks.add_task(
        send_email_background,
        user_data.email.lower(),
        verification_code,
        user_data.first_name
    )
    
    return UserResponse(
        id=user_id,
        email=user_data.email.lower(),
        first_name=user_data.first_name,
        middle_name=user_data.middle_name,
        last_name=user_data.last_name,
        date_of_birth=user_data.date_of_birth,
        created_at=datetime.fromisoformat(user_record_temp["created_at"]),
        is_verified=False,
        message="Account pending verification! Please check your email for verification code. Your account will be active once verified."
    )

@app.post("/verify-email", status_code=status.HTTP_200_OK)
async def verify_email(verification_data: EmailVerification, db: Session = Depends(get_db)):
    """
    Verifies an email address using the provided verification code.
    If successful, creates the user account.
    """
    email = verification_data.email.lower()
    
    pending = db.query(PendingVerification).filter(PendingVerification.email == email).first()
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending verification found for this email."
        )
    
    # Fix: Make both datetimes timezone-aware for comparison
    current_time = datetime.now(timezone.utc)
    
    # Convert pending.expires_at to timezone-aware if it's naive
    if pending.expires_at.tzinfo is None:
        # Assume it's UTC if no timezone info
        expires_at_utc = pending.expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_at_utc = pending.expires_at
    
    if current_time > expires_at_utc:
        db.delete(pending)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired. Please sign up again to get a new code."
        )
    
    if verification_data.verification_code != pending.verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code."
        )
    
    # Parse user data from pending record and create the actual user
    user_data = json.loads(pending.user_data)
    
    new_user = User(
        id=user_data["id"],
        email=user_data["email"],
        first_name=user_data["first_name"],
        middle_name=user_data["middle_name"],
        last_name=user_data["last_name"],
        date_of_birth=date.fromisoformat(user_data["date_of_birth"]),
        password_hash=user_data["password_hash"],
        is_verified=True,
        created_at=datetime.fromisoformat(user_data["created_at"]).replace(tzinfo=timezone.utc),
        verified_at=datetime.now(timezone.utc)
    )
    
    db.add(new_user);
    db.delete(pending);
    db.commit();
    
    return {
        "message": "Email verified successfully! Your account has been created and is now active.",
        "user_id": new_user.id,
        "email": new_user.email,
        "verified_at": new_user.verified_at.isoformat()
    }

@app.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(email: EmailStr, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Resends a verification code to the specified email if a pending verification exists."""
    email = email.lower()
    
    pending = db.query(PendingVerification).filter(PendingVerification.email == email).first()
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending verification found for this email. Please sign up first."
        )
    
    new_verification_code = generate_verification_code()
    
    # Update existing pending verification with new code and expiration
    pending.verification_code = new_verification_code
    pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    db.commit()
    
    user_data = json.loads(pending.user_data)
    
    background_tasks.add_task(
        send_email_background,
        email,
        new_verification_code,
        user_data["first_name"]
    )
    
    return {"message": "Verification code resent successfully. Please check your email."
}

@app.post("/auth/signin", response_model=SignInResponse)
async def signin_user(signin_data: UserSignIn, db: Session = Depends(get_db)):
    """
    Authenticates a user with email and password, returning a JWT token upon success.
    """
    email = signin_data.email.lower()
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    
    if not verify_password(signin_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email first to activate your account."
        )
    
    # Create JWT token with user ID and email in payload
    access_token = create_jwt_token({
        "id": user.id,
        "email": user.email
    })
    
    return SignInResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=JWT_EXPIRATION_HOURS * 3600,
        user={
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "middle_name": user.middle_name,
            "last_name": user.last_name,
            "date_of_birth": user.date_of_birth,
            "created_at": user.created_at,
            "verified_at": user.verified_at
        }
    )

@app.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(forgot_data: ForgotPassword, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Initiates the password reset process by sending a reset code to the user's email."""
    email = forgot_data.email.lower()
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"message": "If the email exists in our system, a password reset code has been sent."}
    
    reset_code = generate_reset_token()  # Now generates a 6-digit OTP
    
    # Remove any existing reset tokens for this email
    db.query(PasswordResetToken).filter(PasswordResetToken.email == email).delete()
    
    # Create new reset token record
    reset_token = PasswordResetToken(
        email=email,
        reset_code=reset_code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30)
    )
    
    db.add(reset_token)
    db.commit()
    
    background_tasks.add_task(
        send_reset_email_background,
        email,
        reset_code,
        user.first_name
    )
    
    return {"message": "If the email exists in our system, a password reset code has been sent."}

# Also fix the reset_password function:
@app.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(reset_data: ResetPassword, db: Session = Depends(get_db)):
    """Resets the user's password using the provided reset code."""
    email = reset_data.email.lower()
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or reset code."
        )
    
    reset_token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.email == email,
        PasswordResetToken.reset_code == reset_data.reset_code
    ).first()
    
    if not reset_token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or reset code."
        )
    
    # Fix: Handle timezone comparison
    current_time = datetime.now(timezone.utc)
    
    # Convert expires_at to timezone-aware if it's naive
    if reset_token_record.expires_at.tzinfo is None:
        expires_at_utc = reset_token_record.expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_at_utc = reset_token_record.expires_at
    
    if current_time > expires_at_utc:
        db.delete(reset_token_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset code has expired. Please request a new one."
        )
    
    # Update user's password and password_updated_at timestamp
    user.password_hash = hash_password(reset_data.new_password)
    user.password_updated_at = datetime.now(timezone.utc)
    
    db.delete(reset_token_record)
    db.commit()
    
    return {
        "message": "Password reset successfully. You can now sign in with your new password.",
        "user_id": user.id
    }

@app.get("/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    """Retrieves the authenticated user's profile information."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        first_name=current_user.first_name,
        middle_name=current_user.middle_name,
        last_name=current_user.last_name,
        date_of_birth=current_user.date_of_birth,
        created_at=current_user.created_at,
        is_verified=current_user.is_verified,
        message="User profile retrieved successfully."
    )

@app.post("/upload-image/")
async def upload_image(current_user: User = Depends(get_current_user), file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image.")
    session_id = str(uuid.uuid4())
    file_extension = file.filename.split('.')[-1].lower()
    image_filename = f"{session_id}.{file_extension}"
    image_path = os.path.join(IMAGE_DIR, image_filename)
    with open(image_path, "wb") as f:
        f.write(await file.read())
    medical_session = MedicalSession(
        id=session_id,
        user_id=current_user.id,
        image_path=image_path,
        status="questioning",
        current_question_index=0
    )
    db.add(medical_session)
    with open(image_path, "rb") as image_file:
        base64_image = base64.b64encode(image_file.read()).decode("utf-8")
    questions = get_initial_questions_from_image(base64_image)
    for i, q_data in enumerate(questions):
        q_id = q_data.get("id", str(uuid.uuid4()))
        medical_question = MedicalQuestion(
            id=q_id,
            session_id=session_id,
            question_text=q_data["question"],
            question_type=q_data.get("type", "text"),
            options=json.dumps(q_data.get("options", [])) if q_data.get("options") else None,
            order_index=i
        )
        db.add(medical_question)
    db.commit()
    current_question = {
        "id": questions[0]["id"],
        "question": questions[0]["question"],
        "type": questions[0].get("type", "text"),
        "options": questions[0].get("options", [])
    } if questions else None
    return {
        "session_id": session_id,
        "status": "questioning",
        "questions": questions,
        "current_question": current_question,
        "image_url": f"/images/{image_filename}"
    }

@app.post("/answer-question/")
async def answer_question(response: QuestionResponse, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session = db.query(MedicalSession).filter(MedicalSession.id == response.session_id).first()
    if not session or session.user_id != current_user.id or session.status != "questioning":
        raise HTTPException(status_code=400, detail="Invalid session.")
    question_answered = db.query(MedicalQuestion).filter(
        MedicalQuestion.session_id == response.session_id,
        MedicalQuestion.id == response.question_id
    ).first()
    if not question_answered:
        raise HTTPException(status_code=400, detail="Question not found.")
    all_questions = db.query(MedicalQuestion).filter(MedicalQuestion.session_id == response.session_id).order_by(MedicalQuestion.order_index).all()
    for idx, q in enumerate(all_questions):
        if q.id == question_answered.id:
            session.current_question_index = idx + 1
            break
    qa_record = MedicalQA(
        session_id=response.session_id,
        question_id=response.question_id,
        question_text=question_answered.question_text,
        answer=response.answer
    )
    db.add(qa_record)
    if session.current_question_index < len(all_questions):
        next_question_db = all_questions[session.current_question_index]
        next_question = {
            "id": next_question_db.id,
            "question": next_question_db.question_text,
            "type": next_question_db.question_type,
            "options": json.loads(next_question_db.options) if next_question_db.options else []
        }
        db.commit()
        return {
            "session_id": response.session_id,
            "status": "questioning",
            "current_question": next_question,
            "questions_remaining": len(all_questions) - session.current_question_index
        }
    else:
        ai_decision = generate_treatment_or_more_questions({"session_id": response.session_id}, db)
        if ai_decision.get("need_more_info", False):
            new_questions = ai_decision.get("questions", [])
            for i, new_q_data in enumerate(new_questions):
                new_q_id = new_q_data.get("id", str(uuid.uuid4()))
                medical_question = MedicalQuestion(
                    id=new_q_id,
                    session_id=response.session_id,
                    question_text=new_q_data["question"],
                    question_type=new_q_data.get("type", "text"),
                    options=json.dumps(new_q_data.get("options", [])) if new_q_data.get("options") else None,
                    order_index=len(all_questions) + i
                )
                db.add(medical_question)
            session.current_question_index = len(all_questions)
            db.commit()
            next_question = {
                "id": new_questions[0]["id"],
                "question": new_questions[0]["question"],
                "type": new_questions[0].get("type", "text"),
                "options": new_questions[0].get("options", [])
            } if new_questions else None
            return {
                "session_id": response.session_id,
                "status": "questioning",
                "current_question": next_question,
                "questions_remaining": len(new_questions)
            }
        else:
            treatment_text = ai_decision.get("treatment", "Consult a professional.")
            session.treatment = treatment_text
            session.status = "completed"
            db.commit()
            return TreatmentResponse(
                session_id=response.session_id,
                treatment=treatment_text,
                session_complete=True
            )

@app.get("/medical-session/{session_id}", response_model=SessionStatus)
async def get_medical_session_status(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session = db.query(MedicalSession).filter(MedicalSession.id == session_id).first()
    if not session or session.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Session not found or access denied.")
    questions = db.query(MedicalQuestion).filter(MedicalQuestion.session_id == session_id).order_by(MedicalQuestion.order_index).all()
    questions_list = [
        {
            "id": q.id,
            "question": q.question_text,
            "type": q.question_type,
            "options": json.loads(q.options) if q.options else []
        }
        for q in questions
    ]
    return SessionStatus(
        session_id=session_id,
        status=session.status,
        questions=questions_list,
        current_question_index=session.current_question_index,
        treatment=session.treatment
    )

@app.get("/my-medical-sessions")
async def get_user_medical_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(MedicalSession).filter(MedicalSession.user_id == current_user.id).order_by(MedicalSession.created_at.desc()).all()
    user_sessions = [
        {
            "session_id": session.id,
            "status": session.status,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "questions_count": db.query(MedicalQuestion).filter(MedicalQuestion.session_id == session.id).count(),
            "answers_count": db.query(MedicalQA).filter(MedicalQA.session_id == session.id).count(),
            "has_treatment": session.treatment is not None
        }
        for session in sessions
    ]
    return {"sessions": user_sessions, "total_sessions": len(user_sessions)}

# Chat System Endpoints
@app.post("/chat/new")
async def create_new_chat(
    request: CreateChatSessionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Creates a new chat session for the user."""
    session_id = str(uuid.uuid4())
    
    chat_session = ChatSession(
        id=session_id,
        user_id=current_user.id
    )
    
    db.add(chat_session)
    db.commit()
    
    return {
        "session_id": session_id,
        "message": "New chat session created successfully.",
        "created_at": chat_session.created_at
    }

@app.post("/chat/message")
async def send_chat_message(
    message: str = Form(...),
    session_id: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Sends a chat message (text and/or image) to the AI and gets a response."""
    
    # Validate file if provided
    if file and file.filename:
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(
                status_code=400, 
                detail="Uploaded file must be an image type (e.g., image/jpeg, image/png)."
            )
    
    # Create or find chat session
    chat_session = None
    if session_id:
        chat_session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
        if chat_session and chat_session.user_id != current_user.id:
            raise HTTPException(
                status_code=403, 
                detail="Access denied: This chat session does not belong to the current user."
            )
    
    if not chat_session:
        session_id = str(uuid.uuid4())
        chat_session = ChatSession(
            id=session_id,
            user_id=current_user.id
        )
        db.add(chat_session)
        db.flush()
    
    # Create user message record
    user_message_record = ChatMessage(
        session_id=chat_session.id,
        user_id=current_user.id,
        content=message,
        is_user=True
    )
    db.add(user_message_record)
    db.flush()  # Get the message ID
    
    # Handle image upload if provided
    image_path = None
    base64_image = None
    if file and file.filename:
        try:
            image_path = save_uploaded_image(file, chat_session.id, user_message_record.id)
            user_message_record.image_path = image_path
            
            # Convert image to base64 for AI analysis
            with open(image_path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode("utf-8")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error processing image: {str(e)}")
    
    # Update session last activity
    chat_session.last_activity = datetime.now(timezone.utc)
    
    # Generate AI response with conversation context
    if base64_image:
        # Use vision model for image analysis with conversation context
        ai_response_text = analyze_image_and_generate_response(
            base64_image, 
            message, 
            current_user,
            chat_session.id,
            db
        )
    else:
        # Use regular chat model for text with full conversation history
        ai_response_text = generate_chat_response(
            message, 
            chat_session.id, 
            current_user,
            db
        )
    
    # Add AI's response to the session history
    ai_message_record = ChatMessage(
        session_id=chat_session.id,
        user_id=current_user.id,
        content=ai_response_text,
        is_user=False
    )
    db.add(ai_message_record)
    db.commit()
    
    return ChatResponseModel(
        response=ai_response_text,
        session_id=chat_session.id,
        message_id=ai_message_record.id,
        timestamp=ai_message_record.created_at
    )

@app.get("/chat/sessions")
async def get_chat_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves a list of all chat sessions for the current user."""
    sessions = db.query(ChatSession).filter(ChatSession.user_id == current_user.id).all()
    
    user_sessions = []
    for session in sessions:
        # Get last message for preview
        last_message = db.query(ChatMessage).filter(
            ChatMessage.session_id == session.id
        ).order_by(ChatMessage.created_at.desc()).first()
        
        message_count = db.query(ChatMessage).filter(ChatMessage.session_id == session.id).count()
        
        # Check if session has any images
        has_images = db.query(ChatMessage).filter(
            ChatMessage.session_id == session.id,
            ChatMessage.image_path.isnot(None)
        ).count() > 0
        
        user_sessions.append({
            "session_id": session.id,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "message_count": message_count,
            "has_images": has_images,
            "last_message": last_message.content[:100] + "..." if last_message and len(last_message.content) > 100 else (last_message.content if last_message else None),
            "last_message_from": "You" if last_message and last_message.is_user else ("AI" if last_message else None),
            "last_message_has_image": last_message.image_path is not None if last_message else False
        })
    
    # Sort sessions by last activity, most recent first
    user_sessions.sort(key=lambda x: x["last_activity"], reverse=True)
    
    return {
        "sessions": user_sessions,
        "total_sessions": len(user_sessions)
    }

@app.get("/chat/session/{session_id}")
async def get_chat_session(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves a specific chat session with all its messages."""
    session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found.")
    
    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied: This chat session does not belong to the current user.")
    
    # Get all messages for this session, ordered by creation time
    messages_in_session = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.created_at).all()
    
    messages_list = []
    for msg in messages_in_session:
        message_data = {
            "id": msg.id,
            "content": msg.content,
            "is_user": msg.is_user,
            "timestamp": msg.created_at,
            "has_image": msg.image_path is not None
        }
        
        # Add image URL if message has an image
        if msg.image_path:
            image_filename = os.path.basename(msg.image_path)
            message_data["image_url"] = f"/images/{image_filename}"
        
        messages_list.append(message_data)
    
    return {
        "session_id": session_id,
        "created_at": session.created_at,
        "last_activity": session.last_activity,
        "messages": messages_list
    }

@app.delete("/chat/session/{session_id}", status_code=status.HTTP_200_OK)
async def delete_chat_session(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Deletes a specific chat session and all its associated messages."""
    session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found.")
    
    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied: This chat session does not belong to the current user.")
    
    # Delete associated image files
    messages_with_images = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id,
        ChatMessage.image_path.isnot(None)
    ).all()
    
    for msg in messages_with_images:
        if msg.image_path and os.path.exists(msg.image_path):
            try:
                os.remove(msg.image_path)
            except Exception as e:
                print(f"Error deleting image file {msg.image_path}: {str(e)}")
    
    # Delete the session (cascade will delete messages)
    db.delete(session)
    db.commit()
    
    return {"message": f"Chat session {session_id} and all related messages deleted successfully."}

@app.delete("/chat/sessions/all", status_code=status.HTTP_200_OK)
async def delete_all_chat_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Deletes all chat sessions for the current user."""
    # Get all user's chat sessions
    sessions_to_delete = db.query(ChatSession).filter(ChatSession.user_id == current_user.id).all()
    session_count = len(sessions_to_delete)
    
    # Delete associated image files
    for session in sessions_to_delete:
        messages_with_images = db.query(ChatMessage).filter(
            ChatMessage.session_id == session.id,
            ChatMessage.image_path.isnot(None)
        ).all()
        
        for msg in messages_with_images:
            if msg.image_path and os.path.exists(msg.image_path):
                try:
                    os.remove(msg.image_path)
                except Exception as e:
                    print(f"Error deleting image file {msg.image_path}: {str(e)}")
    
    # Delete all sessions
    for session in sessions_to_delete:
        db.delete(session)
    
    db.commit()
    
    return {
        "message": f"Deleted {session_count} chat sessions successfully for user {current_user.id}.",
        "deleted_count": session_count
    }

@app.get("/chat/history")
async def get_chat_history(current_user: User = Depends(get_current_user), limit: int = 50, db: Session = Depends(get_db)):
    """Retrieves a paginated list of the user's overall chat history across all sessions."""
    messages = db.query(ChatMessage).filter(
        ChatMessage.user_id == current_user.id
    ).order_by(ChatMessage.created_at.desc()).limit(limit).all()
    
    messages_list = []
    for msg in messages:
        message_data = {
            "id": msg.id,
            "session_id": msg.session_id,
            "content": msg.content,
            "is_user": msg.is_user,
            "timestamp": msg.created_at,
            "has_image": msg.image_path is not None
        }
        
        if msg.image_path:
            image_filename = os.path.basename(msg.image_path)
            message_data["image_url"] = f"/images/{image_filename}"
        
        messages_list.append(message_data)
    
    total_messages = db.query(ChatMessage).filter(ChatMessage.user_id == current_user.id).count()
    
    return {
        "messages": messages_list,
        "total_messages": total_messages,
        "showing": len(messages_list),
        "limit": limit
    }

# Utility Endpoints
@app.get("/users/{email}")
async def get_user_by_email(email: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Retrieves a user's basic information by email.
    Only allows authenticated users to view their own profile for security.
    """
    requested_email = email.lower()
    
    # Security check: Only allow users to view their own profile
    if current_user.email != requested_email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only view your own profile information."
        )
    
    user = db.query(User).filter(User.email == requested_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or email not yet verified."
        )
    
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "middle_name": user.middle_name,
        "last_name": user.last_name,
        "date_of_birth": user.date_of_birth,
        "created_at": user.created_at,
        "is_verified": user.is_verified,
        "verified_at": user.verified_at
    }

@app.get("/dashboard")
async def get_dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Provides a dashboard overview for the authenticated user,
    including chat session statistics and recent activities.
    """
    # Chat session and message statistics
    chat_session_count = db.query(ChatSession).filter(ChatSession.user_id == current_user.id).count()
    total_chat_messages = db.query(ChatMessage).filter(ChatMessage.user_id == current_user.id).count()
    total_images_shared = db.query(ChatMessage).filter(
        ChatMessage.user_id == current_user.id,
        ChatMessage.image_path.isnot(None)
    ).count()
    
    # Recent chat sessions (limit 5)
    recent_chat_sessions = db.query(ChatSession).filter(
        ChatSession.user_id == current_user.id
    ).order_by(ChatSession.last_activity.desc()).limit(5).all()
    
    recent_chat_list = []
    for session in recent_chat_sessions:
        last_message = db.query(ChatMessage).filter(
            ChatMessage.session_id == session.id
        ).order_by(ChatMessage.created_at.desc()).first()
        
        session_has_images = db.query(ChatMessage).filter(
            ChatMessage.session_id == session.id,
            ChatMessage.image_path.isnot(None)
        ).count() > 0
        
        recent_chat_list.append({
            "session_id": session.id,
            "last_activity": session.last_activity,
            "message_count": db.query(ChatMessage).filter(ChatMessage.session_id == session.id).count(),
            "has_images": session_has_images,
            "type": "chat_conversation",
            "last_message_preview": last_message.content[:50] + "..." if last_message and len(last_message.content) > 50 else (last_message.content if last_message else None)
        })
    
    return {
        "user_summary": {
            "name": f"{current_user.first_name} {current_user.last_name}",
            "email": current_user.email,
            "member_since": current_user.created_at,
            "is_verified": current_user.is_verified
        },
        "statistics": {
            "total_chat_sessions": chat_session_count,
            "total_chat_messages": total_chat_messages,
            "total_images_shared": total_images_shared
        },
        "recent_activity": {
            "chat_sessions": recent_chat_list
        }
    }

@app.get("/pending-verifications")
async def get_pending_verifications(db: Session = Depends(get_db)):
    """
    Retrieves all pending email verifications (for testing/admin purposes).
    """
    pending = db.query(PendingVerification).all()
    return {
        "pending_count": len(pending),
        "pending_emails": [p.email for p in pending],
        "details": [{"email": p.email, "expires_at": p.expires_at, "code": p.verification_code} for p in pending]
    }

@app.get("/verified-users")
async def get_verified_users(db: Session = Depends(get_db)):
    """
    Retrieves a count of all verified users (for testing/admin purposes).
    """
    users = db.query(User).filter(User.is_verified == True).all()
    return {
        "verified_users_count": len(users),
        "verified_emails": [u.email for u in users]
    }

@app.get("/system-stats")
async def get_system_stats(db: Session = Depends(get_db)):
    """
    Retrieves overall system statistics (for testing/admin purposes).
    """
    total_users = db.query(User).count()
    pending_verifications = db.query(PendingVerification).count()
    total_chat_sessions = db.query(ChatSession).count()
    total_chat_messages = db.query(ChatMessage).count()
    total_images_shared = db.query(ChatMessage).filter(ChatMessage.image_path.isnot(None)).count()
    password_reset_tokens = db.query(PasswordResetToken).count()
    
    return {
        "total_users": total_users,
        "pending_verifications": pending_verifications,
        "total_chat_sessions": total_chat_sessions,
        "total_chat_messages": total_chat_messages,
        "total_images_shared": total_images_shared,
        "outstanding_password_reset_tokens": password_reset_tokens
    }

@app.get("/download_messages")
async def download_messages(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # In a real application, you'd likely want to restrict this to an admin role.
    if not current_user.is_verified:
        raise HTTPException(status_code=403, detail="User not verified")

    # Fetch all users and their messages
    users = db.query(User).options(joinedload(User.chat_messages)).all()

    # Create a string buffer to hold CSV data
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV header
    writer.writerow(["user_id", "user_email", "message_id", "message_content", "message_timestamp"])

    # Write message data
    for user in users:
        for message in user.chat_messages:
            writer.writerow([user.id, user.email, message.id, message.content, message.created_at.isoformat()])

    # Seek to the beginning of the buffer
    output.seek(0)

    # Return as a streaming response
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=messages.csv"})

@app.get("/download_all_messages_detailed")
async def download_all_messages_detailed(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    format: str = "csv",  # csv, json, excel
    include_images: bool = True,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None
):
    """
    Download all chat messages with detailed user information in various formats
    
    Parameters:
    - format: Output format (csv, json, excel)
    - include_images: Whether to include image information
    - date_from: Filter messages from this date (YYYY-MM-DD)
    - date_to: Filter messages to this date (YYYY-MM-DD)
    """
    
    # Check if user is verified (add admin check if needed)
    if not current_user.is_verified:
        raise HTTPException(status_code=403, detail="User not verified")
    
    # Build base query with comprehensive joins
    query = db.query(
        # User information
        User.id.label('user_id'),
        User.email.label('user_email'),
        User.first_name.label('user_first_name'),
        User.middle_name.label('user_middle_name'),
        User.last_name.label('user_last_name'),
        User.date_of_birth.label('user_date_of_birth'),
        User.created_at.label('user_account_created'),
        User.verified_at.label('user_verified_at'),
        
        # Session information
        ChatSession.id.label('session_id'),
        ChatSession.created_at.label('session_created_at'),
        ChatSession.last_activity.label('session_last_activity'),
        
        # Message information
        ChatMessage.id.label('message_id'),
        ChatMessage.content.label('message_content'),
        ChatMessage.is_user.label('is_user_message'),
        ChatMessage.image_path.label('message_image_path'),
        ChatMessage.created_at.label('message_timestamp')
    ).join(
        ChatSession, User.id == ChatSession.user_id
    ).join(
        ChatMessage, ChatSession.id == ChatMessage.session_id
    )
    
    # Apply date filters if provided
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(ChatMessage.created_at >= date_from_obj)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_from format. Use YYYY-MM-DD")
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, "%Y-%m-%d")
            # Add 1 day to include the entire date_to day
            date_to_obj = date_to_obj.replace(hour=23, minute=59, second=59)
            query = query.filter(ChatMessage.created_at <= date_to_obj)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_to format. Use YYYY-MM-DD")
    
    # Order by user, session, then message timestamp
    query = query.order_by(
        User.email,
        ChatSession.created_at,
        ChatMessage.created_at
    )
    
    # Execute query
    results = query.all()
    
    if not results:
        raise HTTPException(status_code=404, detail="No messages found")
    
    # Process results into structured data
    processed_data = []
    for row in results:
        # Calculate user's full name
        full_name_parts = [row.user_first_name]
        if row.user_middle_name:
            full_name_parts.append(row.user_middle_name)
        full_name_parts.append(row.user_last_name)
        full_name = " ".join(full_name_parts)
        
        # Process image information
        image_filename = None
        image_url = None
        has_image = bool(row.message_image_path)
        
        if include_images and row.message_image_path:
            image_filename = os.path.basename(row.message_image_path)
            image_url = f"/images/{image_filename}"
        
        # Calculate message length and word count
        message_length = len(row.message_content) if row.message_content else 0
        word_count = len(row.message_content.split()) if row.message_content else 0
        
        # Determine sender type
        sender_type = "User" if row.is_user_message else "AI Assistant"
        
        # Calculate user's account age at time of message
        account_age_days = None
        if row.user_account_created and row.message_timestamp:
            account_age = row.message_timestamp - row.user_account_created
            account_age_days = account_age.days
        
        record = {
            # User Information
            'user_id': row.user_id,
            'user_email': row.user_email,
            'user_full_name': full_name,
            'user_first_name': row.user_first_name,
            'user_middle_name': row.user_middle_name or '',
            'user_last_name': row.user_last_name,
            'user_date_of_birth': row.user_date_of_birth.isoformat() if row.user_date_of_birth else '',
            'user_account_created': row.user_account_created.isoformat() if row.user_account_created else '',
            'user_verified_at': row.user_verified_at.isoformat() if row.user_verified_at else '',
            'user_account_age_days': account_age_days,
            
            # Session Information
            'session_id': row.session_id,
            'session_created_at': row.session_created_at.isoformat() if row.session_created_at else '',
            'session_last_activity': row.session_last_activity.isoformat() if row.session_last_activity else '',
            
            # Message Information
            'message_id': row.message_id,
            'message_content': row.message_content or '',
            'message_content_preview': (row.message_content[:100] + '...') if row.message_content and len(row.message_content) > 100 else (row.message_content or ''),
            'message_length': message_length,
            'message_word_count': word_count,
            'sender_type': sender_type,
            'is_user_message': row.is_user_message,
            'message_timestamp': row.message_timestamp.isoformat() if row.message_timestamp else '',
            'message_date': row.message_timestamp.date().isoformat() if row.message_timestamp else '',
            'message_time': row.message_timestamp.time().isoformat() if row.message_timestamp else '',
            
            # Image Information
            'has_image': has_image,
            'image_filename': image_filename or '',
            'image_url': image_url or ''
        }
        
        processed_data.append(record)
    
    # Generate filename with timestamp and filters
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    date_filter_str = ""
    if date_from or date_to:
        date_filter_str = f"_{date_from or 'start'}_to_{date_to or 'end'}"
    
    # Return data in requested format
    if format.lower() == "json":
        return {
            "metadata": {
                "total_messages": len(processed_data),
                "export_timestamp": datetime.now().isoformat(),
                "date_filter": {
                    "from": date_from,
                    "to": date_to
                },
                "include_images": include_images
            },
            "messages": processed_data
        }
    
    # Convert to DataFrame for CSV and Excel export
    df = pd.DataFrame(processed_data)
    
    if format.lower() == "excel":
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Messages')
        
        filename = f"chat_history{date_filter_str}_{timestamp}.xlsx"
        headers = {
            "Content-Disposition": f"attachment; filename={filename}"
        }
        return StreamingResponse(io.BytesIO(output.getvalue()), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers=headers)

    # Default to CSV
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    filename = f"chat_history{date_filter_str}_{timestamp}.csv"
    headers = {
        "Content-Disposition": f"attachment; filename={filename}"
    }
    return StreamingResponse(output, media_type="text/csv", headers=headers)

# Static files (for serving frontend)
@app.get("/{full_path:path}")
async def serve_static_files(full_path: str, request: Request):
    # This is a simple catch-all. In a real-world scenario, you'd want a more robust
    # static file serving solution, likely handled by a web server like Nginx.
    
    # Path to the 'out' directory from the root of your project
    static_dir = os.path.join(os.getcwd(), "frontend", "out")
    
    # Prevent directory traversal attacks
    if ".." in full_path:
        raise HTTPException(status_code=404, detail="Not Found")
        
    file_path = os.path.join(static_dir, full_path)
    
    # Default to index.html for root requests
    if full_path == "" or full_path.endswith("/"):
        file_path = os.path.join(static_dir, "index.html")
        
    # If the requested file doesn't exist, try to serve the corresponding .html file
    if not os.path.exists(file_path):
        html_file_path = os.path.join(static_dir, f"{full_path}.html")
        if os.path.exists(html_file_path):
            file_path = html_file_path
        else:
            # Fallback to index.html for SPA routing
            index_path = os.path.join(static_dir, "index.html")
            if os.path.exists(index_path):
                return FileResponse(index_path)
            else:
                raise HTTPException(status_code=404, detail="Not Found")

    return FileResponse(file_path)