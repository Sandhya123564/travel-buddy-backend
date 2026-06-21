from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks, Query, Header
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import secrets
import shutil

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# SendGrid Configuration
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'noreply@travelbuddy.com')

# File upload directory
UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Create the main app
app = FastAPI(title="Travel Buddy API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ MODELS ============

class UserBase(BaseModel):
    email: EmailStr
    phone: Optional[str] = None

class UserCreate(BaseModel):
    email: EmailStr
    phone: Optional[str] = None
    password: str
    role: str = "traveler"  # traveler | buddy | admin

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    phone: Optional[str] = None
    role: str
    is_verified: bool = False
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class BuddyProfileCreate(BaseModel):
    experience_years: int = 0
    languages: List[str] = []
    bio: Optional[str] = None
    hourly_rate: float = 0

class BuddyProfileResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    experience_years: int
    languages: List[str]
    bio: Optional[str] = None
    hourly_rate: float
    status: str  # pending | verified | rejected
    rating_avg: float = 0
    total_reviews: int = 0
    completed_journeys: int = 0
    user: Optional[dict] = None
    availability: List[str] = []

class BuddyAvailabilityUpdate(BaseModel):
    availability: List[str]  # List of date strings

class FlightCreate(BaseModel):
    flight_number: str
    departure_airport: str
    arrival_airport: str
    travel_date: str

class FlightResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    flight_number: str
    departure_airport: str
    arrival_airport: str
    travel_date: str

class BookingCreate(BaseModel):
    buddy_id: str
    flight_id: Optional[str] = None
    travel_date: str
    departure_airport: str
    arrival_airport: str
    flight_number: Optional[str] = None
    notes: Optional[str] = None
    price: float = 0

class BookingResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    traveler_id: str
    buddy_id: str
    flight_id: Optional[str] = None
    travel_date: str
    departure_airport: str
    arrival_airport: str
    flight_number: Optional[str] = None
    status: str  # requested | accepted | declined | cancelled | completed
    price: float
    notes: Optional[str] = None
    created_at: str
    buddy: Optional[dict] = None
    traveler: Optional[dict] = None

class BookingStatusUpdate(BaseModel):
    status: str

class ReviewCreate(BaseModel):
    booking_id: str
    rating: int  # 1-5
    comment: Optional[str] = None

class ReviewResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    booking_id: str
    traveler_id: str
    buddy_id: str
    rating: int
    comment: Optional[str] = None
    created_at: str
    is_visible: bool = True
    traveler: Optional[dict] = None

class DocumentResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    buddy_id: str
    document_type: str
    file_url: str
    status: str  # pending | approved | rejected
    created_at: str

class BuddySearchQuery(BaseModel):
    travel_date: Optional[str] = None
    departure_airport: Optional[str] = None
    arrival_airport: Optional[str] = None
    flight_number: Optional[str] = None
    language: Optional[str] = None
    min_experience: Optional[int] = None

# ============ HELPER FUNCTIONS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(user_id: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    payload = decode_token(token)
    
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)

async def send_email(to: str, subject: str, content: str):
    """Send email via SendGrid (mocked if no API key)"""
    if not SENDGRID_API_KEY:
        logger.info(f"[MOCK EMAIL] To: {to}")
        logger.info(f"CONTENT: {content}")
        return True
    
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail
        
        message = Mail(
            from_email=SENDER_EMAIL,
            to_emails=to,
            subject=subject,
            html_content=content
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
        return True
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False

# ============ AUTH ENDPOINTS ============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate, background_tasks: BackgroundTasks):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = str(uuid.uuid4())
    otp = generate_otp()
    
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "phone": user_data.phone,
        "password_hash": hash_password(user_data.password),
        "role": user_data.role,
        "is_verified": False,
        "otp": otp,
        "otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user_doc)
    
    # Create buddy profile if role is buddy
    if user_data.role == "buddy":
        buddy_profile = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "experience_years": 0,
            "languages": [],
            "bio": None,
            "hourly_rate": 0,
            "status": "pending",
            "rating_avg": 0,
            "total_reviews": 0,
            "completed_journeys": 0,
            "availability": [],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.buddy_profiles.insert_one(buddy_profile)
    
    # Send OTP email
    background_tasks.add_task(
        send_email,
        user_data.email,
        "Verify your Travel Buddy account",
        f"<h1>Welcome to Travel Buddy!</h1><p>Your verification code is: <strong>{otp}</strong></p>"
    )
    
    token = create_token(user_id, user_data.role)
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            phone=user_data.phone,
            role=user_data.role,
            is_verified=False,
            created_at=user_doc["created_at"]
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["role"])
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            phone=user.get("phone"),
            role=user["role"],
            is_verified=user.get("is_verified", False),
            created_at=user["created_at"]
        )
    )

@api_router.post("/auth/verify-otp")
async def verify_otp(data: OTPVerify):
    user = await db.users.find_one({"email": data.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.get("otp") != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    otp_expires = datetime.fromisoformat(user.get("otp_expires", ""))
    if datetime.now(timezone.utc) > otp_expires:
        raise HTTPException(status_code=400, detail="OTP expired")
    
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"is_verified": True}, "$unset": {"otp": "", "otp_expires": ""}}
    )
    
    return {"message": "Email verified successfully"}

@api_router.post("/auth/resend-otp")
async def resend_otp(email: EmailStr, background_tasks: BackgroundTasks):
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    otp = generate_otp()
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {
            "otp": otp,
            "otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        }}
    )
    
    background_tasks.add_task(
        send_email,
        email,
        "Your new Travel Buddy verification code",
        f"<p>Your new verification code is: <strong>{otp}</strong></p>"
    )
    
    return {"message": "OTP sent"}

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    return UserResponse(
        id=user["id"],
        email=user["email"],
        phone=user.get("phone"),
        role=user["role"],
        is_verified=user.get("is_verified", False),
        created_at=user["created_at"]
    )

# ============ BUDDY PROFILE ENDPOINTS ============

@api_router.get("/buddies", response_model=List[BuddyProfileResponse])
async def search_buddies(
    travel_date: Optional[str] = None,
    departure_airport: Optional[str] = None,
    arrival_airport: Optional[str] = None,
    language: Optional[str] = None,
    min_experience: Optional[int] = None
):
    # Only show verified buddies
    query = {"status": "verified"}
    
    if language:
        query["languages"] = {"$in": [language]}
    if min_experience:
        query["experience_years"] = {"$gte": min_experience}
    if travel_date:
        query["availability"] = {"$in": [travel_date]}
    
    buddies = await db.buddy_profiles.find(query, {"_id": 0}).sort([
        ("rating_avg", -1),
        ("experience_years", -1),
        ("completed_journeys", -1)
    ]).to_list(100)
    
    # Enrich with user data
    for buddy in buddies:
        user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0, "password_hash": 0, "otp": 0})
        buddy["user"] = user
    
    return buddies

@api_router.get("/buddies/{buddy_id}", response_model=BuddyProfileResponse)
async def get_buddy_profile(buddy_id: str):
    buddy = await db.buddy_profiles.find_one({"id": buddy_id}, {"_id": 0})
    if not buddy:
        raise HTTPException(status_code=404, detail="Buddy not found")
    
    user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0, "password_hash": 0, "otp": 0})
    buddy["user"] = user
    
    return buddy

@api_router.get("/buddy/profile", response_model=BuddyProfileResponse)
async def get_my_buddy_profile(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "buddy":
        raise HTTPException(status_code=403, detail="Not a buddy account")
    
    buddy = await db.buddy_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
    if not buddy:
        raise HTTPException(status_code=404, detail="Buddy profile not found")
    
    buddy["user"] = {k: v for k, v in user.items() if k not in ["password_hash", "otp"]}
    return buddy

@api_router.put("/buddy/profile", response_model=BuddyProfileResponse)
async def update_buddy_profile(data: BuddyProfileCreate, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "buddy":
        raise HTTPException(status_code=403, detail="Not a buddy account")
    
    update_data = {
        "experience_years": data.experience_years,
        "languages": data.languages,
        "bio": data.bio,
        "hourly_rate": data.hourly_rate
    }
    
    await db.buddy_profiles.update_one(
        {"user_id": user["id"]},
        {"$set": update_data}
    )
    
    buddy = await db.buddy_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
    buddy["user"] = {k: v for k, v in user.items() if k not in ["password_hash", "otp"]}
    return buddy

@api_router.put("/buddy/availability")
async def update_availability(data: BuddyAvailabilityUpdate, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "buddy":
        raise HTTPException(status_code=403, detail="Not a buddy account")
    
    await db.buddy_profiles.update_one(
        {"user_id": user["id"]},
        {"$set": {"availability": data.availability}}
    )
    
    return {"message": "Availability updated"}

# ============ DOCUMENT ENDPOINTS ============

@api_router.post("/buddy/documents")
async def upload_document(
    document_type: str,
    file: UploadFile = File(...),
    authorization: str = Header(None)
):
    user = await get_current_user(authorization)
    if user["role"] != "buddy":
        raise HTTPException(status_code=403, detail="Not a buddy account")
    
    buddy = await db.buddy_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
    if not buddy:
        raise HTTPException(status_code=404, detail="Buddy profile not found")
    
    # Save file
    file_id = str(uuid.uuid4())
    file_ext = Path(file.filename).suffix
    file_path = UPLOAD_DIR / f"{file_id}{file_ext}"
    
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    
    doc = {
        "id": file_id,
        "buddy_id": buddy["id"],
        "document_type": document_type,
        "file_url": f"/uploads/{file_id}{file_ext}",
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.documents.insert_one(doc)
    
    return DocumentResponse(**doc)

@api_router.get("/buddy/documents", response_model=List[DocumentResponse])
async def get_my_documents(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "buddy":
        raise HTTPException(status_code=403, detail="Not a buddy account")
    
    buddy = await db.buddy_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
    if not buddy:
        return []
    
    docs = await db.documents.find({"buddy_id": buddy["id"]}, {"_id": 0}).to_list(100)
    return docs

# ============ BOOKING ENDPOINTS ============

@api_router.post("/bookings", response_model=BookingResponse)
async def create_booking(data: BookingCreate, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    
    # Verify buddy exists and is verified
    buddy = await db.buddy_profiles.find_one({"id": data.buddy_id}, {"_id": 0})
    if not buddy:
        raise HTTPException(status_code=404, detail="Buddy not found")
    if buddy["status"] != "verified":
        raise HTTPException(status_code=400, detail="Buddy is not verified")
    
    booking_id = str(uuid.uuid4())
    booking_doc = {
        "id": booking_id,
        "traveler_id": user["id"],
        "buddy_id": data.buddy_id,
        "flight_id": data.flight_id,
        "travel_date": data.travel_date,
        "departure_airport": data.departure_airport,
        "arrival_airport": data.arrival_airport,
        "flight_number": data.flight_number,
        "status": "requested",
        "price": data.price or buddy.get("hourly_rate", 0),
        "notes": data.notes,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.bookings.insert_one(booking_doc)
    
    # Send notification to buddy
    buddy_user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0})
    if buddy_user:
        background_tasks.add_task(
            send_email,
            buddy_user["email"],
            "New Booking Request - Travel Buddy",
            f"<h1>New Booking Request</h1><p>You have a new booking request for {data.travel_date}.</p>"
        )
    
    return BookingResponse(**booking_doc)

@api_router.get("/bookings", response_model=List[BookingResponse])
async def get_my_bookings(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    
    if user["role"] == "traveler":
        bookings = await db.bookings.find({"traveler_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    elif user["role"] == "buddy":
        buddy = await db.buddy_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
        if not buddy:
            return []
        bookings = await db.bookings.find({"buddy_id": buddy["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    else:  # admin
        bookings = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    # Enrich with buddy/traveler data
    for booking in bookings:
        buddy = await db.buddy_profiles.find_one({"id": booking["buddy_id"]}, {"_id": 0})
        if buddy:
            buddy_user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0, "password_hash": 0})
            booking["buddy"] = {"profile": buddy, "user": buddy_user}
        
        traveler = await db.users.find_one({"id": booking["traveler_id"]}, {"_id": 0, "password_hash": 0})
        booking["traveler"] = traveler
    
    return bookings

@api_router.put("/bookings/{booking_id}/status")
async def update_booking_status(
    booking_id: str,
    data: BookingStatusUpdate,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None)
):
    user = await get_current_user(authorization)
    
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Authorization check
    if user["role"] == "buddy":
        buddy = await db.buddy_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
        if not buddy or buddy["id"] != booking["buddy_id"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    elif user["role"] == "traveler":
        if user["id"] != booking["traveler_id"]:
            raise HTTPException(status_code=403, detail="Not authorized")
        if data.status not in ["cancelled"]:
            raise HTTPException(status_code=403, detail="Travelers can only cancel bookings")
    
    await db.bookings.update_one(
        {"id": booking_id},
        {"$set": {"status": data.status}}
    )
    
    # Update completed journeys count if completed
    if data.status == "completed":
        await db.buddy_profiles.update_one(
            {"id": booking["buddy_id"]},
            {"$inc": {"completed_journeys": 1}}
        )
    
    # Send notification
    traveler = await db.users.find_one({"id": booking["traveler_id"]}, {"_id": 0})
    if traveler:
        background_tasks.add_task(
            send_email,
            traveler["email"],
            f"Booking {data.status.title()} - Travel Buddy",
            f"<p>Your booking has been {data.status}.</p>"
        )
    
    return {"message": f"Booking {data.status}"}

# ============ REVIEW ENDPOINTS ============

@api_router.post("/reviews", response_model=ReviewResponse)
async def create_review(data: ReviewCreate, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    
    # Verify booking exists and is completed
    booking = await db.bookings.find_one({"id": data.booking_id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["traveler_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your booking")
    if booking["status"] != "completed":
        raise HTTPException(status_code=400, detail="Can only review completed bookings")
    
    # Check if already reviewed
    existing = await db.reviews.find_one({"booking_id": data.booking_id}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Already reviewed")
    
    review_id = str(uuid.uuid4())
    review_doc = {
        "id": review_id,
        "booking_id": data.booking_id,
        "traveler_id": user["id"],
        "buddy_id": booking["buddy_id"],
        "rating": min(5, max(1, data.rating)),
        "comment": data.comment,
        "is_visible": True,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.reviews.insert_one(review_doc)
    
    # Update buddy rating
    reviews = await db.reviews.find(
        {"buddy_id": booking["buddy_id"], "is_visible": True},
        {"_id": 0}
    ).to_list(1000)
    
    if reviews:
        avg_rating = sum(r["rating"] for r in reviews) / len(reviews)
        await db.buddy_profiles.update_one(
            {"id": booking["buddy_id"]},
            {"$set": {"rating_avg": round(avg_rating, 1), "total_reviews": len(reviews)}}
        )
    
    return ReviewResponse(**review_doc)

@api_router.get("/reviews/buddy/{buddy_id}", response_model=List[ReviewResponse])
async def get_buddy_reviews(buddy_id: str):
    reviews = await db.reviews.find(
        {"buddy_id": buddy_id, "is_visible": True},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    for review in reviews:
        traveler = await db.users.find_one({"id": review["traveler_id"]}, {"_id": 0, "password_hash": 0})
        review["traveler"] = traveler
    
    return reviews

# ============ ADMIN ENDPOINTS ============

@api_router.get("/admin/pending-buddies", response_model=List[BuddyProfileResponse])
async def get_pending_buddies(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    buddies = await db.buddy_profiles.find({"status": "pending"}, {"_id": 0}).to_list(100)
    
    for buddy in buddies:
        buddy_user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0, "password_hash": 0})
        buddy["user"] = buddy_user
    
    return buddies

@api_router.get("/admin/buddy/{buddy_id}/documents", response_model=List[DocumentResponse])
async def get_buddy_documents_admin(buddy_id: str, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    docs = await db.documents.find({"buddy_id": buddy_id}, {"_id": 0}).to_list(100)
    return docs

@api_router.put("/admin/buddy/{buddy_id}/verify")
async def verify_buddy(buddy_id: str, status: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if status not in ["verified", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    await db.buddy_profiles.update_one(
        {"id": buddy_id},
        {"$set": {"status": status}}
    )
    
    # Notify buddy
    buddy = await db.buddy_profiles.find_one({"id": buddy_id}, {"_id": 0})
    if buddy:
        buddy_user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0})
        if buddy_user:
            background_tasks.add_task(
                send_email,
                buddy_user["email"],
                f"Profile {status.title()} - Travel Buddy",
                f"<p>Your buddy profile has been {status}.</p>"
            )
    
    return {"message": f"Buddy {status}"}

@api_router.get("/admin/bookings", response_model=List[BookingResponse])
async def get_all_bookings_admin(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    bookings = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    for booking in bookings:
        buddy = await db.buddy_profiles.find_one({"id": booking["buddy_id"]}, {"_id": 0})
        if buddy:
            buddy_user = await db.users.find_one({"id": buddy["user_id"]}, {"_id": 0, "password_hash": 0})
            booking["buddy"] = {"profile": buddy, "user": buddy_user}
        traveler = await db.users.find_one({"id": booking["traveler_id"]}, {"_id": 0, "password_hash": 0})
        booking["traveler"] = traveler
    
    return bookings

@api_router.put("/admin/review/{review_id}/visibility")
async def toggle_review_visibility(review_id: str, is_visible: bool, authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    await db.reviews.update_one(
        {"id": review_id},
        {"$set": {"is_visible": is_visible}}
    )
    
    return {"message": "Review visibility updated"}

@api_router.get("/admin/stats")
async def get_admin_stats(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_users = await db.users.count_documents({})
    total_buddies = await db.buddy_profiles.count_documents({})
    verified_buddies = await db.buddy_profiles.count_documents({"status": "verified"})
    pending_buddies = await db.buddy_profiles.count_documents({"status": "pending"})
    total_bookings = await db.bookings.count_documents({})
    completed_bookings = await db.bookings.count_documents({"status": "completed"})
    
    return {
        "total_users": total_users,
        "total_buddies": total_buddies,
        "verified_buddies": verified_buddies,
        "pending_buddies": pending_buddies,
        "total_bookings": total_bookings,
        "completed_bookings": completed_bookings
    }

# ============ FLIGHTS ENDPOINT ============

@api_router.post("/flights", response_model=FlightResponse)
async def create_flight(data: FlightCreate, authorization: str = Header(None)):
    await get_current_user(authorization)
    
    flight_id = str(uuid.uuid4())
    flight_doc = {
        "id": flight_id,
        "flight_number": data.flight_number,
        "departure_airport": data.departure_airport,
        "arrival_airport": data.arrival_airport,
        "travel_date": data.travel_date
    }
    
    await db.flights.insert_one(flight_doc)
    return FlightResponse(**flight_doc)

@api_router.get("/flights", response_model=List[FlightResponse])
async def search_flights(
    flight_number: Optional[str] = None,
    departure_airport: Optional[str] = None,
    arrival_airport: Optional[str] = None,
    travel_date: Optional[str] = None
):
    query = {}
    if flight_number:
        query["flight_number"] = {"$regex": flight_number, "$options": "i"}
    if departure_airport:
        query["departure_airport"] = {"$regex": departure_airport, "$options": "i"}
    if arrival_airport:
        query["arrival_airport"] = {"$regex": arrival_airport, "$options": "i"}
    if travel_date:
        query["travel_date"] = travel_date
    
    flights = await db.flights.find(query, {"_id": 0}).to_list(100)
    return flights

# ============ HEALTH CHECK ============

@api_router.get("/")
async def root():
    return {"message": "Travel Buddy API"}

@api_router.get("/health")
async def health():
    return {"status": "healthy"}

# Include the router
app.include_router(api_router)

# Serve uploaded files
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create default admin on startup
@app.on_event("startup")
async def create_default_admin():
    admin_email = "admin@travelbuddy.com"
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        admin_doc = {
            "id": str(uuid.uuid4()),
            "email": admin_email,
            "phone": None,
            "password_hash": hash_password("Admin123!"),
            "role": "admin",
            "is_verified": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(admin_doc)
        logger.info("Default admin created: admin@travelbuddy.com / Admin123!")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
import os
import uvicorn

if _name_ == "_main_":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=False
    )