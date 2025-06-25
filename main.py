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
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
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
    
    # Relationships
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

class ChatSession(Base):
    """SQLAlchemy model for chat sessions."""
    __tablename__ = "chat_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")

class ChatMessage(Base):
    """SQLAlchemy model for individual chat messages."""
    __tablename__ = "chat_messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("chat_sessions.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    is_user = Column(Boolean, nullable=False)  # True if from user, False if from AI
    image_path = Column(String, nullable=True)  # Path to uploaded image if any
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

# Security scheme for JWT authentication
security = HTTPBearer()

# Email configuration
SMTP_SERVER = " mail.privateemail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("EMAIL_ADDRESS")
SMTP_PASSWORD = os.getenv("EMAIL_PASSWORD")

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
    payload = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    """Verifies and decodes a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
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

# Email Functions
def send_verification_email(email: str, verification_code: str, first_name: str):
    """Sends a verification email to the user."""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Verify Your Account - Verification Code"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your Account</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
            <table role="presentation" style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 40px 0; text-align: center;">
                        <table role="presentation" style="width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <tr>
                                <td style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 40px 30px; text-align: center; border-radius: 8px 8px 0 0;">
                                    <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">Athlix</h1>
                                    <p style="color: #ffffff; margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Welcome! Please verify your account</p>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 40px 30px;">
                                    <div style="text-align: center; margin-bottom: 30px;">
                                        <div style="width: 60px; height: 60px; background: linear-gradient(135deg, #28a745 0%, #20c997 100%); border-radius: 50%; margin: 0 auto 15px auto; display: flex; align-items: center; justify-content: center;">
                                            <span style="color: white; font-size: 24px;">✓</span>
                                        </div>
                                    </div>
                                    
                                    <h2 style="color: #333333; margin: 0 0 20px 0; font-size: 24px; text-align: center;">Hi {first_name}!</h2>
                                    
                                    <p style="color: #666666; font-size: 16px; line-height: 1.6; margin: 0 0 25px 0; text-align: center;">
                                        🎉 Welcome to <strong>Athlix</strong>! We're excited to have you on board.
                                    </p>
                                    
                                    <p style="color: #666666; font-size: 16px; line-height: 1.6; margin: 0 0 25px 0;">
                                        To complete your account setup and ensure the security of your account, please verify your email address using the code below:
                                    </p>
                                    
                                    <div style="background: linear-gradient(135deg, #e8f5e8 0%, #d4edda 100%); border: 2px solid #28a745; border-radius: 8px; padding: 25px; text-align: center; margin: 25px 0;">
                                        <p style="margin: 0 0 10px 0; color: #333333; font-size: 14px; font-weight: bold;">Your Verification Code:</p>
                                        <p style="margin: 0; font-size: 36px; font-weight: bold; color: #28a745; letter-spacing: 4px; font-family: 'Courier New', monospace;">{verification_code}</p>
                                    </div>
                                    
                                    <div style="background-color: #fff8e1; border-left: 4px solid #ffc107; padding: 15px; border-radius: 4px; margin: 25px 0;">
                                        <p style="color: #856404; font-size: 14px; margin: 0; font-weight: bold;">
                                            ⏰ Quick Action Required: This code will expire in 15 minutes for security reasons.
                                        </p>
                                    </div>
                                    
                                    <p style="color: #666666; font-size: 16px; line-height: 1.6; margin: 25px 0 0 0;">
                                        If you didn't create an account with Athlix, please ignore this email. No further action is required.
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-radius: 0 0 8px 8px; border-top: 1px solid #e9ecef;">
                                    <p style="margin: 0 0 10px 0; color: #333333; font-size: 16px; font-weight: bold;">Welcome to the team!</p>
                                    <p style="margin: 0; color: #28a745; font-size: 18px; font-weight: bold;">The Athlix Team</p>
                                    
                                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e9ecef;">
                                        <p style="margin: 0; color: #999999; font-size: 12px;">
                                            This is an automated message. Please do not reply to this email.
                                        </p>
                                    </div>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))

        # Use STARTTLS on port 587
        server = smtplib.SMTP("mail.privateemail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, email, text)
        server.quit()
        print(f"Verification email sent to {email}")

    except Exception as e:
        print(f"Failed to send verification email to {email}: {str(e)}")

def send_password_reset_email(email: str, reset_code: str, first_name: str):
    """Sends a password reset email to the user with an embedded logo."""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Password Reset Request"

        # HTML email body with CID reference for the logo
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Request</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" style="width: 100%; border-collapse: collapse;">
        <tr>
            <td style="padding: 40px 0; text-align: center;">
                <table role="presentation" style="width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
                    <tr>
                        <td style="padding: 50px 30px; text-align: center; border-radius: 12px 12px 0 0;">
                            <img src="cid:athlix_logo" alt="Athlix Logo" style="max-width: 160px; height: auto; margin-bottom: 15px; border-radius: 8px;">
                            <p style="color: #555555; margin: 12px 0 0 0; font-size: 18px; font-weight: 400;">Password Reset Request</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 50px 40px;">
                            <h2 style="color: #333333; margin: 0 0 25px 0; font-size: 26px; font-weight: 600;">Hi {first_name},</h2>
                            
                            <p style="color: #555555; font-size: 16px; line-height: 1.7; margin: 0 0 30px 0;">
                                We received a request to reset your password for your Athlix account. Use the code below to reset your password:
                            </p>
                            
                            <div style="background-color: #f8f9fa; border: 2px dashed #667eea; border-radius: 10px; padding: 25px; text-align: center; margin: 30px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                                <p style="margin: 0 0 12px 0; color: #333333; font-size: 15px; font-weight: 600;">Your Reset Code:</p>
                                <p id="resetCode" style="margin: 0 0 15px 0; font-size: 36px; font-weight: 700; color: #667eea; letter-spacing: 4px; font-family: 'Courier New', Courier, monospace;">{reset_code}</p>
                                <button onclick="copyCode()" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; border: none; padding: 12px 24px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; transition: opacity 0.3s;">Copy Code</button>
                                <p style="color: #999999; font-size: 12px; margin: 10px 0 0 0;">(Clicking may not work in all email clients. Please copy the code manually if needed.)</p>
                            </div>
                            
                            <p style="color: #555555; font-size: 16px; line-height: 1.7; margin: 30px 0;">
                                <strong>Important:</strong> This code will expire in 30 minutes for security reasons.
                            </p>
                            
                            <p style="color: #555555; font-size: 16px; line-height: 1.7; margin: 30px 0 0 0;">
                                If you didn't request a password reset, please ignore this email. Your account remains secure.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 40px; text-align: center; border-radius: 0 0 12px 12px; border-top: 1px solid #e9ecef;">
                            <p style="margin: 0 0 12px 0; color: #333333; font-size: 18px; font-weight: 600;">Best regards,</p>
                            <p style="margin: 0; color: #667eea; font-size: 20px; font-weight: 700;">The Athlix Team</p>
                            
                            <div style="margin-top: 25px; padding-top: 25px; border-top: 1px solid #e9ecef;">
                                <p style="margin: 0; color: #999999; font-size: 13px;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
    <script>
        function copyCode() {{
            let code = document.getElementById('resetCode').innerText;
            navigator.clipboard.writeText(code).then(() => {{
                alert('Code copied to clipboard!');
            }}).catch(() => {{
                alert('Failed to copy code. Please copy it manually.');
            }});
        }}
    </script>
</body>
</html>
        """

        # Attach the HTML body
        msg.attach(MIMEText(html_body, 'html'))

        # Attach the logo image as a CID resource
        with open("frontend/public/logo.png", "rb") as image_file:
            logo = MIMEImage(image_file.read(), name="logo.png")
            logo.add_header('Content-ID', '<athlix_logo>')
            logo.add_header('Content-Disposition', 'inline', filename="logo.png")
            msg.attach(logo)

        # Send the email
        server = smtplib.SMTP("mail.privateemail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, email, text)
        server.quit()
        print(f"Verification email sent to {email}")

    except Exception as e:
        print(f"Failed to send password reset email to {email}: {str(e)}")

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
        
    except Exception as e:
        print(f"Error analyzing image with AI: {str(e)}")
        return f"I'm sorry {user_data.first_name}, I'm having trouble analyzing the image right now. Could you describe your concern in text, and I'll do my best to help you based on our previous conversations."


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
    chat_session.last_activity = datetime.utcnow()
    
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

def save_uploaded_image(file: UploadFile, session_id: str, message_id: str) -> str:
    """
    Saves an uploaded image file and returns the file path.
    """
    try:
        file_extension = file.filename.split('.')[-1].lower() if file.filename else 'jpg'
        image_filename = f"{session_id}_{message_id}.{file_extension}"
        image_path = os.path.join(IMAGE_DIR, image_filename)
        with open(image_path, "wb") as f:
            f.write(file.file.read())
        return image_path
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving image: {str(e)}")

# --- API Endpoints ---

# Authentication Endpoints
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
        if datetime.utcnow() > pending.expires_at:
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
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Store pending verification in database
    pending_verification = PendingVerification(
        email=user_data.email.lower(),
        verification_code=verification_code,
        expires_at=datetime.utcnow() + timedelta(minutes=15),
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
    
    if datetime.utcnow() > pending.expires_at:
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
        created_at=datetime.fromisoformat(user_data["created_at"]),
        verified_at=datetime.utcnow()
    )
    
    db.add(new_user)
    db.delete(pending)
    db.commit()
    
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
    pending.expires_at = datetime.utcnow() + timedelta(minutes=15)
    
    db.commit()
    
    user_data = json.loads(pending.user_data)
    
    background_tasks.add_task(
        send_email_background,
        email,
        new_verification_code,
        user_data["first_name"]
    )
    
    return {"message": "Verification code resent successfully. Please check your email."}

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
        expires_at=datetime.utcnow() + timedelta(minutes=30)
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
    
    if datetime.utcnow() > reset_token_record.expires_at:
        db.delete(reset_token_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset code has expired. Please request a new one."
        )
    
    # Update user's password and password_updated_at timestamp
    user.password_hash = hash_password(reset_data.new_password)
    user.password_updated_at = datetime.utcnow()
    
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
    chat_session.last_activity = datetime.utcnow()
    
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

@app.get("/")
async def root():
    """Root endpoint providing API information and setup instructions."""
    return {
        "message": "Complete Medical & Authentication API with Integrated Chat System",
        "version": "3.0.0",
        "database": "SQLAlchemy with SQLite (default) / PostgreSQL",
        "features": [
            "Secure User Authentication (Signup, Signin, Email Verification, Password Reset)",
            "JWT-based Authorization for protected endpoints",
            "Integrated Chat System with AI Assistant",
            "Medical Image Analysis with AI (OpenAI Vision)",
            "Text and Image Support in Chat Messages",
            "AI-powered Medical Consultation and Health Advice",
            "Session Management for Chat Conversations",
            "Image Upload and Storage with Chat Messages",
            "Robust Database Storage for all user and chat data",
            "Comprehensive Dashboard for user activity overview"
        ],
        "endpoints_summary": {
            "Authentication & User": {
                "/signup (POST)": "Create new user account (requires email verification)",
                "/verify-email (POST)": "Verify email with code to activate account",
                "/resend-verification (POST)": "Resend email verification code",
                "/auth/signin (POST)": "Sign in and get JWT access token",
                "/forgot-password (POST)": "Request password reset code via email",
                "/reset-password (POST)": "Reset password using code",
                "/profile (GET)": "Get current user's profile (protected)",
                "/users/{email} (GET)": "Get user details by email (protected, self-only)",
                "/dashboard (GET)": "User's activity dashboard (protected)"
            },
            "Chat System with Medical AI": {
                "/chat/new (POST)": "Create a new chat session (protected)",
                "/chat/message (POST)": "Send message (text and/or image) to AI chat assistant (protected)",
                "/chat/sessions (GET)": "List all chat sessions for the user (protected)",
                "/chat/session/{session_id} (GET)": "Get a specific chat session with messages (protected)",
                "/chat/session/{session_id} (DELETE)": "Delete a specific chat session (protected)",
                "/chat/sessions/all (DELETE)": "Delete all chat sessions for the user (protected)",
                "/chat/history (GET)": "Get overall chat message history (protected)"
            },
            "Admin/Testing Endpoints": {
                "/pending-verifications (GET)": "View all pending email verifications",
                "/verified-users (GET)": "View count of verified users",
                "/system-stats (GET)": "Get overall system statistics"
            },
            "Static Files & Documentation": {
                "/images/{filename} (GET)": "Access uploaded images",
                "/docs (GET)": "OpenAPI interactive documentation (Swagger UI)"
            }
        },
        "chat_system_details": {
            "message_types": [
                "Text only messages",
                "Image only messages",
                "Combined text and image messages"
            ],
            "ai_capabilities": [
                "Medical image analysis and consultation",
                "Health and wellness advice",
                "Fitness and workout guidance",
                "Injury prevention tips",
                "General medical information",
                "Conversational support and follow-up questions"
            ],
            "image_support": {
                "formats": "JPEG, PNG, and other common image formats",
                "storage": "Images stored locally with database references",
                "access": "Images accessible via /images/{filename} endpoint",
                "ai_analysis": "OpenAI Vision API for medical image analysis"
            }
        },
        "authentication_details": {
            "type": "Bearer Token (JWT)",
            "header": "Authorization: Bearer <your-jwt-token>",
            "token_expiration": f"{JWT_EXPIRATION_HOURS} hours"
        },
        "setup_instructions": {
            "1": "Install dependencies: `pip install fastapi 'uvicorn[standard]' sqlalchemy python-dotenv 'openai>=1.0.0' 'Pillow' 'email-validator' python-multipart`",
            "2": [
                "Create a `.env` file in the project root with the following variables:",
                "`DATABASE_URL=\"sqlite:///./medical_app.db\"` (or your PostgreSQL URL)",
                "`EMAIL_ADDRESS=\"your_email@gmail.com\"` (Your Gmail address for sending emails)",
                "`EMAIL_PASSWORD=\"your_gmail_app_password\"` (Generate this from Google Account security settings)",
                "`OPENAI_API_KEY=\"your_openai_api_key_here\"` (Your API key for OpenAI services)",
                "`JWT_SECRET_KEY=\"a_very_strong_random_secret_key_for_production\"` (Generate with `secrets.token_urlsafe(32)`)"
            ],
            "3": "Run the application: `uvicorn main:app --reload` (replace 'main' with your file name)",
            "4": "Access API documentation at: `http://127.0.0.1:8000/docs`",
            "5": "Upload images and chat with the AI at the various chat endpoints"
        },
        "database_models_overview": {
            "users": "User accounts with authentication details",
            "pending_verifications": "Temporary records for email verification codes",
            "password_reset_tokens": "Temporary records for password reset codes",
            "chat_sessions": "Records for each AI chat conversation",
            "chat_messages": "Individual messages within chat sessions (user and AI) with optional image paths"
        },
        "api_usage_examples": {
            "create_chat": "POST /chat/new",
            "send_text_message": "POST /chat/message with form data: message='Hello, I have a question about my health'",
            "send_image_message": "POST /chat/message with form data: message='Please analyze this image' and file upload",
            "send_combined_message": "POST /chat/message with both message text and image file",
            "get_chat_history": "GET /chat/session/{session_id}"
        },
        "notes": [
            "All chat messages support both text and image content",
            "Images are automatically analyzed by AI when uploaded",
            "Chat sessions persist user conversation history",
            "AI provides medical consultation but recommends professional healthcare for serious concerns",
            "Remember to keep your API keys and secrets secure",
            "For production, consider more robust email services and PostgreSQL database"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)