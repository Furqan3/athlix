from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, validator
from datetime import date, datetime, timedelta
from typing import Optional, List, Dict, Any
import hashlib
import secrets
import smtplib
import os
import jwt
import json
import uuid
import io
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from openai import OpenAI
from dotenv import load_dotenv
from PIL import Image
import base64

# Database imports
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer, ForeignKey, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# Load environment variables from .env file
load_dotenv()

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./medical_app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Directory for uploaded images
IMAGE_DIR = os.path.join(os.getcwd(), "uploaded_images")
if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

# Database Models
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

class PendingVerification(Base):
    """SQLAlchemy model for pending email verifications."""
    __tablename__ = "pending_verifications"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    verification_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    user_data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class PasswordResetToken(Base):
    """SQLAlchemy model for password reset tokens."""
    __tablename__ = "password_reset_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, index=True, nullable=False)
    reset_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

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

class ChatSession(Base):
    """SQLAlchemy model for chat sessions."""
    __tablename__ = "chat_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = relationship("User", back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")

class ChatMessage(Base):
    """SQLAlchemy model for individual chat messages."""
    __tablename__ = "chat_messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("chat_sessions.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=True)  # Allow null for image-only messages
    image_path = Column(String, nullable=True)  # Path to image if present
    is_user = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    session = relationship("ChatSession", back_populates="messages")
    user = relationship("User", back_populates="chat_messages")

# Create database tables
Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Complete Medical & Authentication API", version="2.0.0")

# Mount static files directory for uploaded images
app.mount("/images", StaticFiles(directory=IMAGE_DIR), name="images")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

security = HTTPBearer()

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("EMAIL_ADDRESS")
SMTP_PASSWORD = os.getenv("EMAIL_PASSWORD")

# OpenAI client initialization
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Pydantic Models
class UserSignup(BaseModel):
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
    email: EmailStr
    verification_code: str

class UserSignIn(BaseModel):
    email: EmailStr
    password: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
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
    access_token: str
    token_type: str
    expires_in: int
    user: dict

class UserResponse(BaseModel):
    id: str
    email: str
    first_name: str
    middle_name: Optional[str]
    last_name: str
    date_of_birth: date
    created_at: datetime
    is_verified: bool
    message: str

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

class ChatResponseModel(BaseModel):
    response: str
    session_id: str
    message_id: str
    timestamp: datetime

# Authentication Helper Functions
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"

def verify_password(password: str, hashed_password: str) -> bool:
    try:
        salt, pwd_hash = hashed_password.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except ValueError:
        return False

def create_jwt_token(user_data: dict) -> str:
    payload = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    payload = verify_jwt_token(token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials: User ID missing from token.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or token invalid.")
    return user

def generate_verification_code() -> str:
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)

# Email Functions
def send_verification_email(email: str, verification_code: str, first_name: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Verify Your Account - Verification Code"
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h1>Athlix</h1>
            <p>Welcome! Please verify your account</p>
            <h2>Hi {first_name}!</h2>
            <p>Your Verification Code: <strong>{verification_code}</strong></p>
            <p>This code will expire in 15 minutes.</p>
            <p>If you didn't create an account with Athlix, please ignore this email.</p>
            <p>The Athlix Team</p>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, msg.as_string())
        server.quit()
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Failed to send verification email to {email}: {str(e)}")

def send_password_reset_email(email: str, reset_code: str, first_name: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Password Reset Request"
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h1>Athlix</h1>
            <p>Password Reset Request</p>
            <h2>Hi {first_name},</h2>
            <p>Your Reset Code: <strong>{reset_code}</strong></p>
            <p>This code will expire in 30 minutes.</p>
            <p>If you didn't request a password reset, please ignore this email.</p>
            <p>The Athlix Team</p>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, msg.as_string())
        server.quit()
        print(f"Password reset email sent to {email}")
    except Exception as e:
        print(f"Failed to send password reset email to {email}: {str(e)}")

def send_email_background(email: str, verification_code: str, first_name: str):
    thread = Thread(target=send_verification_email, args=(email, verification_code, first_name))
    thread.start()

def send_reset_email_background(email: str, reset_code: str, first_name: str):
    thread = Thread(target=send_password_reset_email, args=(email, reset_code, first_name))
    thread.start()

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
                    "content": """You are a medical assessment AI. Analyze the provided image and generate important questions.
                    Return a JSON object:
                    {
                        "questions": [
                            {"id": "q1", "question": "Your question", "type": "text|multiple_choice|number", "options": ["option1", "option2"]}
                        ]
                    }
                    Generate 3-5 relevant questions."""
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
                    "content": """You are a trainer and injury expert. Based on the history, decide if you can provide recommendations or need more questions.
                    Return JSON:
                    1. {"need_more_info": true, "questions": [{"id": "q1", "question": "...", "type": "..."}]}
                    2. {"need_more_info": false, "treatment": "..."}"""
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
    except Exception as e:
        print(f"Error in AI response: {str(e)}")
        return {"need_more_info": False, "treatment": "Consult a professional."}

def generate_chat_response(user_message: str, session_id: str, user_data: User, db: Session) -> str:
    try:
        messages = [
            {
                "role": "system",
                "content": f"""You are a helpful medical AI assistant for {user_data.first_name}.
                You can help with general health, fitness, injury prevention, wellness, and basic medical info.
                Be supportive and friendly. Remind users to consult professionals for serious concerns."""
            }
        ]
        chat_history = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at).limit(10).all()
        for msg in chat_history:
            if msg.is_user:
                content = msg.content if msg.content else "[Image attached]" if msg.image_path else ""
                messages.append({"role": "user", "content": content})
            else:
                messages.append({"role": "assistant", "content": msg.content})
        messages.append({"role": "user", "content": user_message})
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=500,
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error generating chat response: {str(e)}")
        return "Sorry, I'm having trouble responding. Please try again later."

# API Endpoints
@app.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup_user(user_data: UserSignup, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user_data.email.lower()).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered.")
    pending = db.query(PendingVerification).filter(PendingVerification.email == user_data.email.lower()).first()
    if pending and datetime.utcnow() <= pending.expires_at:
        raise HTTPException(status_code=400, detail="Email has pending verification.")
    elif pending:
        db.delete(pending)
        db.commit()
    user_id = str(uuid.uuid4())
    verification_code = generate_verification_code()
    hashed_password = hash_password(user_data.password)
    user_record_temp = {
        "id": user_id,
        "email": user_data.email.lower(),
        "first_name": user_data.first_name,
        "middle_name": user_data.middle_name,
        "last_name": user_data.last_name,
        "date_of_birth": user_data.date_of_birth.isoformat(),
        "password_hash": hashed_password,
        "created_at": datetime.utcnow().isoformat()
    }
    pending_verification = PendingVerification(
        email=user_data.email.lower(),
        verification_code=verification_code,
        expires_at=datetime.utcnow() + timedelta(minutes=15),
        user_data=json.dumps(user_record_temp)
    )
    db.add(pending_verification)
    db.commit()
    background_tasks.add_task(send_email_background, user_data.email.lower(), verification_code, user_data.first_name)
    return UserResponse(
        id=user_id,
        email=user_data.email.lower(),
        first_name=user_data.first_name,
        middle_name=user_data.middle_name,
        last_name=user_data.last_name,
        date_of_birth=user_data.date_of_birth,
        created_at=datetime.fromisoformat(user_record_temp["created_at"]),
        is_verified=False,
        message="Account pending verification! Check your email."
    )

@app.post("/verify-email", status_code=status.HTTP_200_OK)
async def verify_email(verification_data: EmailVerification, db: Session = Depends(get_db)):
    email = verification_data.email.lower()
    pending = db.query(PendingVerification).filter(PendingVerification.email == email).first()
    if not pending:
        raise HTTPException(status_code=400, detail="No pending verification found.")
    if datetime.utcnow() > pending.expires_at:
        db.delete(pending)
        db.commit()
        raise HTTPException(status_code=400, detail="Verification code expired.")
    if verification_data.verification_code != pending.verification_code:
        raise HTTPException(status_code=400, detail="Invalid verification code.")
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
        created_at=datetime.fromisoformat(user_data["created_at"]),
        verified_at=datetime.utcnow()
    )
    db.add(new_user)
    db.delete(pending)
    db.commit()
    return {"message": "Email verified successfully!", "user_id": new_user.id, "email": new_user.email}

@app.post("/auth/signin", response_model=SignInResponse)
async def signin_user(signin_data: UserSignIn, db: Session = Depends(get_db)):
    email = signin_data.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(signin_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified.")
    access_token = create_jwt_token({"id": user.id, "email": user.email})
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
    email = forgot_data.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"message": "If the email exists, a reset code has been sent."}
    reset_code = generate_reset_token()
    db.query(PasswordResetToken).filter(PasswordResetToken.email == email).delete()
    reset_token = PasswordResetToken(
        email=email,
        reset_code=reset_code,
        expires_at=datetime.utcnow() + timedelta(minutes=30)
    )
    db.add(reset_token)
    db.commit()
    background_tasks.add_task(send_reset_email_background, email, reset_code, user.first_name)
    return {"message": "If the email exists, a reset code has been sent."}

@app.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(reset_data: ResetPassword, db: Session = Depends(get_db)):
    email = reset_data.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or reset code.")
    reset_token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.email == email,
        PasswordResetToken.reset_code == reset_data.reset_code
    ).first()
    if not reset_token_record or datetime.utcnow() > reset_token_record.expires_at:
        if reset_token_record:
            db.delete(reset_token_record)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired reset code.")
    user.password_hash = hash_password(reset_data.new_password)
    user.password_updated_at = datetime.utcnow()
    db.delete(reset_token_record)
    db.commit()
    return {"message": "Password reset successfully.", "user_id": user.id}

@app.get("/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
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

@app.post("/chat", response_model=ChatResponseModel)
async def send_chat_message(
    message: Optional[str] = Form(None),
    image: UploadFile = File(None),
    session_id: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if message is None and image is None:
        raise HTTPException(status_code=400, detail="Message or image must be provided.")
    chat_session = None
    if session_id:
        chat_session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not chat_session:
        session_id = str(uuid.uuid4())
        chat_session = ChatSession(id=session_id, user_id=current_user.id)
        db.add(chat_session)
        db.flush()
    if chat_session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied.")
    user_message_record = ChatMessage(
        session_id=chat_session.id,
        user_id=current_user.id,
        content=message,
        is_user=True
    )
    db.add(user_message_record)
    db.flush()
    if image:
        file_extension = image.filename.split('.')[-1].lower()
        image_filename = f"chat_{user_message_record.id}.{file_extension}"
        image_path = os.path.join(IMAGE_DIR, image_filename)
        with open(image_path, "wb") as f:
            f.write(await image.read())
        user_message_record.image_path = image_path
    user_message_content = message if message is not None else "[Image attached]"
    ai_response_text = generate_chat_response(user_message_content, chat_session.id, current_user, db)
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

@app.get("/chat-sessions")
async def get_chat_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(ChatSession).filter(ChatSession.user_id == current_user.id).all()
    user_sessions = []
    for session in sessions:
        last_message = db.query(ChatMessage).filter(ChatMessage.session_id == session.id).order_by(ChatMessage.created_at.desc()).first()
        message_count = db.query(ChatMessage).filter(ChatMessage.session_id == session.id).count()
        user_sessions.append({
            "session_id": session.id,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "message_count": message_count,
            "last_message": last_message.content[:100] + "..." if last_message and len(last_message.content) > 100 else (last_message.content if last_message else None),
            "last_message_from": "You" if last_message and last_message.is_user else ("AI" if last_message else None)
        })
    user_sessions.sort(key=lambda x: x["last_activity"], reverse=True)
    return {"sessions": user_sessions, "total_sessions": len(user_sessions)}

@app.get("/chat-session/{session_id}")
async def get_chat_session(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session or session.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Session not found or access denied.")
    messages = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at).all()
    messages_list = [
        {
            "id": msg.id,
            "content": msg.content,
            "image_url": f"/images/{os.path.basename(msg.image_path)}" if msg.image_path else None,
            "is_user": msg.is_user,
            "timestamp": msg.created_at
        }
        for msg in messages
    ]
    return {
        "session_id": session_id,
        "created_at": session.created_at,
        "last_activity": session.last_activity,
        "messages": messages_list
    }

@app.get("/chat-history")
async def get_chat_history(current_user: User = Depends(get_current_user), limit: int = 50, db: Session = Depends(get_db)):
    messages = db.query(ChatMessage).filter(ChatMessage.user_id == current_user.id).order_by(ChatMessage.created_at.desc()).limit(limit).all()
    messages_list = [
        {
            "id": msg.id,
            "session_id": msg.session_id,
            "content": msg.content,
            "image_url": f"/images/{os.path.basename(msg.image_path)}" if msg.image_path else None,
            "is_user": msg.is_user,
            "timestamp": msg.created_at
        }
        for msg in messages
    ]
    total_messages = db.query(ChatMessage).filter(ChatMessage.user_id == current_user.id).count()
    return {
        "messages": messages_list,
        "total_messages": total_messages,
        "showing": len(messages_list),
        "limit": limit
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)