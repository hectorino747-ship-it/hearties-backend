"""
Hearties Social - Backend API
A fandom-focused social media platform
"""

import os
import secrets
import base64
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt

load_dotenv()

# =============================================================================
# Configuration
# =============================================================================

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "hearties_social")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# =============================================================================
# Database Connection
# =============================================================================

client = None
db = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global client, db
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("username", unique=True)
    await db.posts.create_index([("created_at", -1)])
    await db.fandoms.create_index("slug", unique=True)
    
    # Seed initial fandoms
    await seed_fandoms()
    
    print("Connected to MongoDB")
    yield
    client.close()
    print("Disconnected from MongoDB")

app = FastAPI(
    title="Hearties Social API",
    description="A fandom-focused social media platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Pydantic Models
# =============================================================================

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=6)
    display_name: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    profile_picture: Optional[str] = None  # Base64 encoded

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    display_name: Optional[str]
    bio: Optional[str]
    profile_picture: Optional[str]
    role: str
    is_verified: bool
    joined_fandoms: List[str]
    followers_count: int
    following_count: int
    posts_count: int
    created_at: datetime
    invite_code: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class PostCreate(BaseModel):
    content: str = Field(..., max_length=5000)
    fandom_id: str
    post_type: str = "text"  # text, image, fan_art, meme, theory, discussion
    hashtags: Optional[List[str]] = []
    image: Optional[str] = None  # Base64 encoded

class PostResponse(BaseModel):
    id: str
    user_id: str
    username: str
    display_name: Optional[str]
    user_profile_picture: Optional[str]
    is_verified: bool
    content: str
    image: Optional[str]
    fandom_id: str
    fandom_name: str
    fandom_slug: str
    post_type: str
    hashtags: List[str]
    likes_count: int
    comments_count: int
    is_liked: bool
    created_at: datetime

class CommentCreate(BaseModel):
    content: str = Field(..., max_length=1000)
    parent_id: Optional[str] = None

class CommentResponse(BaseModel):
    id: str
    post_id: str
    user_id: str
    username: str
    display_name: Optional[str]
    user_profile_picture: Optional[str]
    is_verified: bool
    content: str
    parent_id: Optional[str]
    likes_count: int
    is_liked: bool
    created_at: datetime

class FandomResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: str
    banner_image: Optional[str]
    icon: str
    color: str
    members_count: int
    posts_count: int
    is_joined: bool
    created_at: datetime

class FollowResponse(BaseModel):
    success: bool
    is_following: bool
    followers_count: int

class ReportCreate(BaseModel):
    reason: str = Field(..., max_length=500)
    report_type: str = "inappropriate"  # inappropriate, spam, harassment, other

class ReportResponse(BaseModel):
    id: str
    reporter_id: str
    target_type: str  # post, user, comment
    target_id: str
    reason: str
    report_type: str
    status: str  # pending, reviewed, resolved, dismissed
    created_at: datetime

# Stories Models
class StoryCreate(BaseModel):
    media_type: str = "image"  # image or video
    media_url: Optional[str] = None
    media_base64: Optional[str] = None
    caption: Optional[str] = None

class StoryResponse(BaseModel):
    id: str
    user_id: str
    username: str
    display_name: Optional[str]
    profile_picture: Optional[str]
    media_type: str
    media_url: Optional[str]
    caption: Optional[str]
    views_count: int
    created_at: datetime
    expires_at: datetime
    is_viewed: bool = False

# Messages Models
class MessageCreate(BaseModel):
    content: str = Field(..., max_length=2000)
    media_base64: Optional[str] = None
    media_type: Optional[str] = None  # image, video

class ConversationResponse(BaseModel):
    id: str
    participant: dict
    last_message: Optional[dict]
    unread_count: int
    updated_at: datetime

class MessageResponse(BaseModel):
    id: str
    conversation_id: str
    sender_id: str
    content: str
    media_url: Optional[str]
    media_type: Optional[str]
    is_read: bool
    created_at: datetime

# =============================================================================
# Helper Functions
# =============================================================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_invite_code(username: str) -> str:
    return f"{username.lower()}-{secrets.token_urlsafe(4)}"

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    print(f"Auth credentials received: {credentials.credentials[:30]}..." if credentials else "No credentials")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        print(f"User ID from token: {user_id}")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError as e:
        print(f"JWT Error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        print(f"User not found for ID: {user_id}")
        raise HTTPException(status_code=401, detail="User not found")
    
    print(f"User found: {user.get('username')}, role: {user.get('role')}")
    return user

async def get_optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))):
    if credentials is None:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id:
            user = await db.users.find_one({"_id": ObjectId(user_id)})
            return user
    except:
        pass
    return None

def serialize_user(user: dict, followers_count: int = 0, following_count: int = 0, posts_count: int = 0) -> UserResponse:
    return UserResponse(
        id=str(user["_id"]),
        email=user["email"],
        username=user["username"],
        display_name=user.get("display_name"),
        bio=user.get("bio"),
        profile_picture=user.get("profile_picture"),
        role=user.get("role", "user"),
        is_verified=user.get("is_verified", False),
        joined_fandoms=user.get("joined_fandoms", []),
        followers_count=followers_count,
        following_count=following_count,
        posts_count=posts_count,
        created_at=user.get("created_at", datetime.utcnow()),
        invite_code=user.get("invite_code", "")
    )

# =============================================================================
# Seed Data
# =============================================================================

INITIAL_FANDOMS = [
    # General/All category - for everyone
    {
        "name": "All",
        "slug": "all",
        "description": "The global community! Share anything and everything with all Hearties members.",
        "icon": "globe",
        "color": "#8B5CF6"
    },
    # Original fandoms
    {
        "name": "Marvel",
        "slug": "marvel",
        "description": "Earth's Mightiest Heroes and beyond! Discuss MCU movies, comics, and all things Marvel.",
        "icon": "shield",
        "color": "#E23636"
    },
    {
        "name": "Star Wars",
        "slug": "star-wars",
        "description": "May the Force be with you. The galaxy far, far away awaits.",
        "icon": "star",
        "color": "#FFE81F"
    },
    {
        "name": "Anime",
        "slug": "anime",
        "description": "Your gateway to Japanese animation. From shonen to slice of life.",
        "icon": "film",
        "color": "#FF69B4"
    },
    {
        "name": "Gaming",
        "slug": "gaming",
        "description": "Level up your discussions. PC, console, mobile - all gamers welcome!",
        "icon": "game-controller",
        "color": "#9B59B6"
    },
    {
        "name": "K-Pop",
        "slug": "kpop",
        "description": "Stan your favorites! The hottest Korean pop music community.",
        "icon": "musical-notes",
        "color": "#FF1493"
    },
    {
        "name": "Movies",
        "slug": "movies",
        "description": "Lights, camera, discussion! All cinema lovers unite here.",
        "icon": "videocam",
        "color": "#3498DB"
    },
    {
        "name": "TV Series",
        "slug": "tv-series",
        "description": "Binge-worthy content discussions. From dramas to sitcoms.",
        "icon": "tv",
        "color": "#2ECC71"
    },
    {
        "name": "Stranger Things",
        "slug": "stranger-things",
        "description": "Enter the Upside Down. Hawkins awaits your theories!",
        "icon": "flash",
        "color": "#E74C3C"
    },
    {
        "name": "Music Fans",
        "slug": "music-fans",
        "description": "All genres, all artists. Share your musical passion.",
        "icon": "headset",
        "color": "#F39C12"
    },
    {
        "name": "Comics",
        "slug": "comics",
        "description": "From DC to indie publishers. Graphic novel enthusiasts welcome!",
        "icon": "book",
        "color": "#1ABC9C"
    },
    # New Gaming fandoms
    {
        "name": "Minecraft",
        "slug": "minecraft",
        "description": "Build, explore, survive! The blocky world of endless possibilities.",
        "icon": "cube",
        "color": "#5D8731"
    },
    {
        "name": "Roblox",
        "slug": "roblox",
        "description": "Play together, create together. The ultimate gaming platform community.",
        "icon": "apps",
        "color": "#E2231A"
    },
    {
        "name": "Free Fire",
        "slug": "free-fire",
        "description": "Battle royale fans unite! Drop in and share your victories.",
        "icon": "flame",
        "color": "#FF6B00"
    },
    # New TV Series fandoms
    {
        "name": "Welcome to Derry",
        "slug": "welcome-to-derry",
        "description": "Return to Derry. The IT prequel universe awaits the brave.",
        "icon": "balloon",
        "color": "#8B0000"
    },
    {
        "name": "Dark",
        "slug": "dark",
        "description": "Time is an illusion. Discuss the German sci-fi masterpiece.",
        "icon": "time",
        "color": "#1A1A2E"
    },
    {
        "name": "Heartstopper",
        "slug": "heartstopper",
        "description": "Nick and Charlie's story. A wholesome LGBTQ+ romance community.",
        "icon": "heart",
        "color": "#FFB6C1"
    },
    {
        "name": "Young Hearts",
        "slug": "young-hearts",
        "description": "Follow the journey of young love and self-discovery.",
        "icon": "heart-half",
        "color": "#FF69B4"
    },
    {
        "name": "Wednesday",
        "slug": "wednesday",
        "description": "Snap snap! Join the Nevermore Academy community.",
        "icon": "skull",
        "color": "#2C2C2C"
    },
    {
        "name": "Elite",
        "slug": "elite",
        "description": "Las Encinas drama. Spanish teen thriller discussions.",
        "icon": "school",
        "color": "#C41E3A"
    },
    {
        "name": "Los 100",
        "slug": "los-100",
        "description": "The 100 - Survival of the fittest. Post-apocalyptic drama fans.",
        "icon": "nuclear",
        "color": "#228B22"
    },
    {
        "name": "La Casa de Papel",
        "slug": "la-casa-de-papel",
        "description": "Money Heist! Bella Ciao! Join the resistance.",
        "icon": "cash",
        "color": "#FF0000"
    },
    {
        "name": "XOXO, Kitty",
        "slug": "xoxo-kitty",
        "description": "Follow Kitty's adventures in Seoul. To All The Boys spin-off.",
        "icon": "mail",
        "color": "#FF85A2"
    },
]

async def seed_fandoms():
    """Seed initial fandom communities if they don't exist"""
    for fandom_data in INITIAL_FANDOMS:
        existing = await db.fandoms.find_one({"slug": fandom_data["slug"]})
        if not existing:
            await db.fandoms.insert_one({
                **fandom_data,
                "banner_image": None,
                "members_count": 0,
                "posts_count": 0,
                "created_at": datetime.utcnow(),
                "created_by": "system"
            })
    print("Fandoms seeded successfully")

# =============================================================================
# Authentication Endpoints
# =============================================================================

@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    """Register a new user"""
    # Check if email exists
    existing_email = await db.users.find_one({"email": user_data.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if username exists
    existing_username = await db.users.find_one({"username": user_data.username.lower()})
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Check if this is the first user (becomes owner)
    user_count = await db.users.count_documents({})
    role = "owner" if user_count == 0 else "user"
    
    # Create user
    user_doc = {
        "email": user_data.email,
        "username": user_data.username.lower(),
        "display_name": user_data.display_name or user_data.username,
        "password_hash": get_password_hash(user_data.password),
        "bio": None,
        "profile_picture": None,
        "role": role,
        "is_verified": role == "owner",  # Owner is auto-verified
        "joined_fandoms": [],
        "invite_code": generate_invite_code(user_data.username),
        "invited_by": None,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    
    # Create token
    access_token = create_access_token({"sub": str(result.inserted_id)})
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=serialize_user(user_doc)
    )

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Login user"""
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Get counts
    followers_count = await db.follows.count_documents({"following_id": str(user["_id"])})
    following_count = await db.follows.count_documents({"follower_id": str(user["_id"])})
    posts_count = await db.posts.count_documents({"user_id": str(user["_id"])})
    
    access_token = create_access_token({"sub": str(user["_id"])})
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=serialize_user(user, followers_count, following_count, posts_count)
    )

@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    followers_count = await db.follows.count_documents({"following_id": str(current_user["_id"])})
    following_count = await db.follows.count_documents({"follower_id": str(current_user["_id"])})
    posts_count = await db.posts.count_documents({"user_id": str(current_user["_id"])})
    
    return serialize_user(current_user, followers_count, following_count, posts_count)

# =============================================================================
# User Profile Endpoints
# =============================================================================

@app.put("/api/users/profile", response_model=UserResponse)
async def update_profile(
    update_data: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update user profile"""
    update_fields = {}
    if update_data.display_name is not None:
        update_fields["display_name"] = update_data.display_name
    if update_data.bio is not None:
        update_fields["bio"] = update_data.bio
    if update_data.profile_picture is not None:
        update_fields["profile_picture"] = update_data.profile_picture
    
    if update_fields:
        await db.users.update_one(
            {"_id": current_user["_id"]},
            {"$set": update_fields}
        )
    
    updated_user = await db.users.find_one({"_id": current_user["_id"]})
    followers_count = await db.follows.count_documents({"following_id": str(current_user["_id"])})
    following_count = await db.follows.count_documents({"follower_id": str(current_user["_id"])})
    posts_count = await db.posts.count_documents({"user_id": str(current_user["_id"])})
    
    return serialize_user(updated_user, followers_count, following_count, posts_count)

@app.get("/api/users/blocked")
async def get_blocked_users(current_user: dict = Depends(get_current_user)):
    """Get list of blocked users"""
    blocks = await db.blocks.find({"blocker_id": str(current_user["_id"])}).to_list(100)
    
    blocked_users = []
    for block in blocks:
        try:
            user = await db.users.find_one({"_id": ObjectId(block["blocked_id"])})
            if user:
                blocked_users.append({
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "display_name": user.get("display_name"),
                    "profile_picture": user.get("profile_picture")
                })
        except:
            continue
    
    return {"blocked_users": blocked_users}

@app.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, current_user: dict = Depends(get_optional_user)):
    """Get user profile by ID"""
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    followers_count = await db.follows.count_documents({"following_id": user_id})
    following_count = await db.follows.count_documents({"follower_id": user_id})
    posts_count = await db.posts.count_documents({"user_id": user_id})
    
    return serialize_user(user, followers_count, following_count, posts_count)

@app.get("/api/users/username/{username}", response_model=UserResponse)
async def get_user_by_username(username: str, current_user: dict = Depends(get_optional_user)):
    """Get user profile by username"""
    user = await db.users.find_one({"username": username.lower()})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = str(user["_id"])
    followers_count = await db.follows.count_documents({"following_id": user_id})
    following_count = await db.follows.count_documents({"follower_id": user_id})
    posts_count = await db.posts.count_documents({"user_id": user_id})
    
    return serialize_user(user, followers_count, following_count, posts_count)

# =============================================================================
# Follow System Endpoints
# =============================================================================

@app.post("/api/users/{user_id}/follow", response_model=FollowResponse)
async def toggle_follow(user_id: str, current_user: dict = Depends(get_current_user)):
    """Follow or unfollow a user"""
    if str(current_user["_id"]) == user_id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")
    
    # Check if target user exists
    try:
        target_user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    follower_id = str(current_user["_id"])
    
    # Check if already following
    existing = await db.follows.find_one({
        "follower_id": follower_id,
        "following_id": user_id
    })
    
    if existing:
        # Unfollow
        await db.follows.delete_one({"_id": existing["_id"]})
        is_following = False
    else:
        # Follow
        await db.follows.insert_one({
            "follower_id": follower_id,
            "following_id": user_id,
            "created_at": datetime.utcnow()
        })
        is_following = True
    
    followers_count = await db.follows.count_documents({"following_id": user_id})
    
    return FollowResponse(
        success=True,
        is_following=is_following,
        followers_count=followers_count
    )

@app.get("/api/users/{user_id}/is-following")
async def check_is_following(user_id: str, current_user: dict = Depends(get_current_user)):
    """Check if current user is following target user"""
    existing = await db.follows.find_one({
        "follower_id": str(current_user["_id"]),
        "following_id": user_id
    })
    return {"is_following": existing is not None}

@app.get("/api/users/{user_id}/followers")
async def get_followers(user_id: str, skip: int = 0, limit: int = 20):
    """Get user's followers"""
    follows = await db.follows.find({"following_id": user_id}).skip(skip).limit(limit).to_list(limit)
    
    followers = []
    for follow in follows:
        user = await db.users.find_one({"_id": ObjectId(follow["follower_id"])})
        if user:
            followers.append({
                "id": str(user["_id"]),
                "username": user["username"],
                "display_name": user.get("display_name"),
                "profile_picture": user.get("profile_picture"),
                "is_verified": user.get("is_verified", False)
            })
    
    return {"followers": followers}

@app.get("/api/users/{user_id}/following")
async def get_following(user_id: str, skip: int = 0, limit: int = 20):
    """Get users that this user is following"""
    follows = await db.follows.find({"follower_id": user_id}).skip(skip).limit(limit).to_list(limit)
    
    following = []
    for follow in follows:
        user = await db.users.find_one({"_id": ObjectId(follow["following_id"])})
        if user:
            following.append({
                "id": str(user["_id"]),
                "username": user["username"],
                "display_name": user.get("display_name"),
                "profile_picture": user.get("profile_picture"),
                "is_verified": user.get("is_verified", False)
            })
    
    return {"following": following}

# =============================================================================
# Fandom Endpoints
# =============================================================================

@app.get("/api/fandoms")
async def get_fandoms(current_user: dict = Depends(get_optional_user)):
    """Get all fandoms"""
    fandoms = await db.fandoms.find().sort("members_count", -1).to_list(100)
    
    user_joined = current_user.get("joined_fandoms", []) if current_user else []
    
    return [{
        "id": str(f["_id"]),
        "name": f["name"],
        "slug": f["slug"],
        "description": f["description"],
        "banner_image": f.get("banner_image"),
        "icon": f["icon"],
        "color": f["color"],
        "members_count": f.get("members_count", 0),
        "posts_count": f.get("posts_count", 0),
        "is_joined": str(f["_id"]) in user_joined,
        "created_at": f.get("created_at", datetime.utcnow())
    } for f in fandoms]

@app.get("/api/fandoms/{fandom_id}")
async def get_fandom(fandom_id: str, current_user: dict = Depends(get_optional_user)):
    """Get fandom details"""
    try:
        fandom = await db.fandoms.find_one({"_id": ObjectId(fandom_id)})
    except:
        # Try by slug
        fandom = await db.fandoms.find_one({"slug": fandom_id})
    
    if not fandom:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    user_joined = current_user.get("joined_fandoms", []) if current_user else []
    
    return {
        "id": str(fandom["_id"]),
        "name": fandom["name"],
        "slug": fandom["slug"],
        "description": fandom["description"],
        "banner_image": fandom.get("banner_image"),
        "icon": fandom["icon"],
        "color": fandom["color"],
        "members_count": fandom.get("members_count", 0),
        "posts_count": fandom.get("posts_count", 0),
        "is_joined": str(fandom["_id"]) in user_joined,
        "created_at": fandom.get("created_at", datetime.utcnow())
    }

@app.post("/api/fandoms/{fandom_id}/join")
async def toggle_join_fandom(fandom_id: str, current_user: dict = Depends(get_current_user)):
    """Join or leave a fandom"""
    try:
        fandom = await db.fandoms.find_one({"_id": ObjectId(fandom_id)})
    except:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    if not fandom:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    user_fandoms = current_user.get("joined_fandoms", [])
    
    if fandom_id in user_fandoms:
        # Leave fandom
        user_fandoms.remove(fandom_id)
        await db.fandoms.update_one({"_id": fandom["_id"]}, {"$inc": {"members_count": -1}})
        is_joined = False
    else:
        # Join fandom
        user_fandoms.append(fandom_id)
        await db.fandoms.update_one({"_id": fandom["_id"]}, {"$inc": {"members_count": 1}})
        is_joined = True
    
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"joined_fandoms": user_fandoms}}
    )
    
    fandom = await db.fandoms.find_one({"_id": ObjectId(fandom_id)})
    
    return {
        "success": True,
        "is_joined": is_joined,
        "members_count": fandom.get("members_count", 0)
    }

# Pydantic model for creating fandoms
class FandomCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., max_length=500)
    icon: str = Field(default="planet")  # Ionicons icon name
    color: str = Field(default="#8B5CF6")  # Hex color

@app.post("/api/fandoms")
async def create_fandom(fandom_data: FandomCreate, current_user: dict = Depends(get_current_user)):
    """Create a new fandom (owner only)"""
    # Only owner can create fandoms
    if current_user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Only the platform owner can create fandoms")
    
    # Generate slug from name
    slug = fandom_data.name.lower().replace(" ", "-").replace("'", "")
    
    # Check if fandom already exists
    existing = await db.fandoms.find_one({"slug": slug})
    if existing:
        raise HTTPException(status_code=400, detail="A fandom with this name already exists")
    
    # Create fandom
    fandom_doc = {
        "name": fandom_data.name,
        "slug": slug,
        "description": fandom_data.description,
        "icon": fandom_data.icon,
        "color": fandom_data.color,
        "banner_image": None,
        "members_count": 0,
        "posts_count": 0,
        "created_at": datetime.utcnow(),
        "created_by": str(current_user["_id"])
    }
    
    result = await db.fandoms.insert_one(fandom_doc)
    
    return {
        "id": str(result.inserted_id),
        "name": fandom_doc["name"],
        "slug": fandom_doc["slug"],
        "description": fandom_doc["description"],
        "icon": fandom_doc["icon"],
        "color": fandom_doc["color"],
        "members_count": 0,
        "posts_count": 0,
        "is_joined": False,
        "created_at": fandom_doc["created_at"]
    }

@app.put("/api/fandoms/{fandom_id}")
async def update_fandom(fandom_id: str, fandom_data: FandomCreate, current_user: dict = Depends(get_current_user)):
    """Update a fandom (owner only)"""
    if current_user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Only the platform owner can update fandoms")
    
    try:
        fandom = await db.fandoms.find_one({"_id": ObjectId(fandom_id)})
    except:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    if not fandom:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    # Update fandom
    await db.fandoms.update_one(
        {"_id": ObjectId(fandom_id)},
        {"$set": {
            "name": fandom_data.name,
            "description": fandom_data.description,
            "icon": fandom_data.icon,
            "color": fandom_data.color
        }}
    )
    
    updated = await db.fandoms.find_one({"_id": ObjectId(fandom_id)})
    
    return {
        "id": str(updated["_id"]),
        "name": updated["name"],
        "slug": updated["slug"],
        "description": updated["description"],
        "icon": updated["icon"],
        "color": updated["color"],
        "members_count": updated.get("members_count", 0),
        "posts_count": updated.get("posts_count", 0),
        "is_joined": False,
        "created_at": updated.get("created_at", datetime.utcnow())
    }

@app.delete("/api/fandoms/{fandom_id}")
async def delete_fandom(fandom_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a fandom (owner only)"""
    if current_user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Only the platform owner can delete fandoms")
    
    try:
        fandom = await db.fandoms.find_one({"_id": ObjectId(fandom_id)})
    except:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    if not fandom:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    # Don't allow deleting the "All" fandom
    if fandom.get("slug") == "all":
        raise HTTPException(status_code=400, detail="Cannot delete the 'All' fandom")
    
    # Delete fandom and all associated posts
    await db.fandoms.delete_one({"_id": ObjectId(fandom_id)})
    await db.posts.delete_many({"fandom_id": fandom_id})
    
    # Remove fandom from users' joined_fandoms
    await db.users.update_many(
        {"joined_fandoms": fandom_id},
        {"$pull": {"joined_fandoms": fandom_id}}
    )
    
    return {"success": True, "message": f"Fandom '{fandom['name']}' has been deleted"}

# =============================================================================
# Post Endpoints
# =============================================================================

@app.post("/api/posts")
async def create_post(post_data: PostCreate, current_user: dict = Depends(get_current_user)):
    """Create a new post"""
    # Validate fandom
    try:
        fandom = await db.fandoms.find_one({"_id": ObjectId(post_data.fandom_id)})
    except:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    if not fandom:
        raise HTTPException(status_code=404, detail="Fandom not found")
    
    # Create post
    post_doc = {
        "user_id": str(current_user["_id"]),
        "content": post_data.content,
        "image": post_data.image,
        "fandom_id": post_data.fandom_id,
        "post_type": post_data.post_type,
        "hashtags": post_data.hashtags or [],
        "likes_count": 0,
        "comments_count": 0,
        "created_at": datetime.utcnow()
    }
    
    result = await db.posts.insert_one(post_doc)
    
    # Update fandom post count
    await db.fandoms.update_one({"_id": fandom["_id"]}, {"$inc": {"posts_count": 1}})
    
    return {
        "id": str(result.inserted_id),
        "user_id": post_doc["user_id"],
        "username": current_user["username"],
        "display_name": current_user.get("display_name"),
        "user_profile_picture": current_user.get("profile_picture"),
        "is_verified": current_user.get("is_verified", False),
        "content": post_doc["content"],
        "image": post_doc["image"],
        "fandom_id": post_doc["fandom_id"],
        "fandom_name": fandom["name"],
        "fandom_slug": fandom["slug"],
        "post_type": post_doc["post_type"],
        "hashtags": post_doc["hashtags"],
        "likes_count": 0,
        "comments_count": 0,
        "is_liked": False,
        "created_at": post_doc["created_at"]
    }

@app.get("/api/posts")
async def get_posts(
    fandom_id: Optional[str] = None,
    user_id: Optional[str] = None,
    post_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
    current_user: dict = Depends(get_optional_user)
):
    """Get posts with optional filters"""
    query = {}
    
    if fandom_id:
        query["fandom_id"] = fandom_id
    if user_id:
        query["user_id"] = user_id
    if post_type:
        query["post_type"] = post_type
    
    posts = await db.posts.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for post in posts:
        user = await db.users.find_one({"_id": ObjectId(post["user_id"])})
        fandom = await db.fandoms.find_one({"_id": ObjectId(post["fandom_id"])})
        
        is_liked = False
        if current_user:
            like = await db.likes.find_one({
                "user_id": str(current_user["_id"]),
                "post_id": str(post["_id"])
            })
            is_liked = like is not None
        
        result.append({
            "id": str(post["_id"]),
            "user_id": post["user_id"],
            "username": user["username"] if user else "deleted",
            "display_name": user.get("display_name") if user else None,
            "user_profile_picture": user.get("profile_picture") if user else None,
            "is_verified": user.get("is_verified", False) if user else False,
            "content": post["content"],
            "image": post.get("image"),
            "fandom_id": post["fandom_id"],
            "fandom_name": fandom["name"] if fandom else "Unknown",
            "fandom_slug": fandom["slug"] if fandom else "unknown",
            "post_type": post.get("post_type", "text"),
            "hashtags": post.get("hashtags", []),
            "likes_count": post.get("likes_count", 0),
            "comments_count": post.get("comments_count", 0),
            "is_liked": is_liked,
            "created_at": post.get("created_at", datetime.utcnow())
        })
    
    return result

@app.get("/api/posts/feed")
async def get_home_feed(skip: int = 0, limit: int = 20, current_user: dict = Depends(get_current_user)):
    """Get personalized home feed based on joined fandoms and followed users"""
    user_fandoms = current_user.get("joined_fandoms", [])
    
    # Get followed users
    follows = await db.follows.find({"follower_id": str(current_user["_id"])}).to_list(1000)
    followed_user_ids = [f["following_id"] for f in follows]
    
    # Build query: posts from joined fandoms OR followed users
    query = {"$or": []}
    if user_fandoms:
        query["$or"].append({"fandom_id": {"$in": user_fandoms}})
    if followed_user_ids:
        query["$or"].append({"user_id": {"$in": followed_user_ids}})
    
    # If no filters, get all posts
    if not query["$or"]:
        query = {}
    
    posts = await db.posts.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for post in posts:
        user = await db.users.find_one({"_id": ObjectId(post["user_id"])})
        fandom = await db.fandoms.find_one({"_id": ObjectId(post["fandom_id"])})
        
        like = await db.likes.find_one({
            "user_id": str(current_user["_id"]),
            "post_id": str(post["_id"])
        })
        
        result.append({
            "id": str(post["_id"]),
            "user_id": post["user_id"],
            "username": user["username"] if user else "deleted",
            "display_name": user.get("display_name") if user else None,
            "user_profile_picture": user.get("profile_picture") if user else None,
            "is_verified": user.get("is_verified", False) if user else False,
            "content": post["content"],
            "image": post.get("image"),
            "fandom_id": post["fandom_id"],
            "fandom_name": fandom["name"] if fandom else "Unknown",
            "fandom_slug": fandom["slug"] if fandom else "unknown",
            "post_type": post.get("post_type", "text"),
            "hashtags": post.get("hashtags", []),
            "likes_count": post.get("likes_count", 0),
            "comments_count": post.get("comments_count", 0),
            "is_liked": like is not None,
            "created_at": post.get("created_at", datetime.utcnow())
        })
    
    return result

@app.get("/api/posts/{post_id}")
async def get_post(post_id: str, current_user: dict = Depends(get_optional_user)):
    """Get single post by ID"""
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
    except:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    user = await db.users.find_one({"_id": ObjectId(post["user_id"])})
    fandom = await db.fandoms.find_one({"_id": ObjectId(post["fandom_id"])})
    
    is_liked = False
    if current_user:
        like = await db.likes.find_one({
            "user_id": str(current_user["_id"]),
            "post_id": post_id
        })
        is_liked = like is not None
    
    return {
        "id": str(post["_id"]),
        "user_id": post["user_id"],
        "username": user["username"] if user else "deleted",
        "display_name": user.get("display_name") if user else None,
        "user_profile_picture": user.get("profile_picture") if user else None,
        "is_verified": user.get("is_verified", False) if user else False,
        "content": post["content"],
        "image": post.get("image"),
        "fandom_id": post["fandom_id"],
        "fandom_name": fandom["name"] if fandom else "Unknown",
        "fandom_slug": fandom["slug"] if fandom else "unknown",
        "post_type": post.get("post_type", "text"),
        "hashtags": post.get("hashtags", []),
        "likes_count": post.get("likes_count", 0),
        "comments_count": post.get("comments_count", 0),
        "is_liked": is_liked,
        "created_at": post.get("created_at", datetime.utcnow())
    }

@app.delete("/api/posts/{post_id}")
async def delete_post(post_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a post (owner, admin, or post author only)"""
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
    except:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Check permissions
    is_author = post["user_id"] == str(current_user["_id"])
    is_admin = current_user.get("role") in ["admin", "owner"]
    
    if not is_author and not is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete this post")
    
    await db.posts.delete_one({"_id": ObjectId(post_id)})
    await db.likes.delete_many({"post_id": post_id})
    await db.comments.delete_many({"post_id": post_id})
    
    # Update fandom post count
    await db.fandoms.update_one(
        {"_id": ObjectId(post["fandom_id"])},
        {"$inc": {"posts_count": -1}}
    )
    
    return {"success": True}

# =============================================================================
# Like Endpoints
# =============================================================================

@app.post("/api/posts/{post_id}/like")
async def toggle_like_post(post_id: str, current_user: dict = Depends(get_current_user)):
    """Like or unlike a post"""
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
    except:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    user_id = str(current_user["_id"])
    
    existing = await db.likes.find_one({
        "user_id": user_id,
        "post_id": post_id
    })
    
    if existing:
        # Unlike
        await db.likes.delete_one({"_id": existing["_id"]})
        await db.posts.update_one({"_id": ObjectId(post_id)}, {"$inc": {"likes_count": -1}})
        is_liked = False
    else:
        # Like
        await db.likes.insert_one({
            "user_id": user_id,
            "post_id": post_id,
            "created_at": datetime.utcnow()
        })
        await db.posts.update_one({"_id": ObjectId(post_id)}, {"$inc": {"likes_count": 1}})
        is_liked = True
    
    post = await db.posts.find_one({"_id": ObjectId(post_id)})
    
    return {
        "success": True,
        "is_liked": is_liked,
        "likes_count": post.get("likes_count", 0)
    }

# =============================================================================
# Comment Endpoints
# =============================================================================

@app.post("/api/posts/{post_id}/comments")
async def create_comment(
    post_id: str,
    comment_data: CommentCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a comment on a post"""
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
    except:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    comment_doc = {
        "post_id": post_id,
        "user_id": str(current_user["_id"]),
        "content": comment_data.content,
        "parent_id": comment_data.parent_id,
        "likes_count": 0,
        "created_at": datetime.utcnow()
    }
    
    result = await db.comments.insert_one(comment_doc)
    
    # Update post comment count
    await db.posts.update_one({"_id": ObjectId(post_id)}, {"$inc": {"comments_count": 1}})
    
    return {
        "id": str(result.inserted_id),
        "post_id": post_id,
        "user_id": str(current_user["_id"]),
        "username": current_user["username"],
        "display_name": current_user.get("display_name"),
        "user_profile_picture": current_user.get("profile_picture"),
        "is_verified": current_user.get("is_verified", False),
        "content": comment_doc["content"],
        "parent_id": comment_doc["parent_id"],
        "likes_count": 0,
        "is_liked": False,
        "created_at": comment_doc["created_at"]
    }

@app.get("/api/posts/{post_id}/comments")
async def get_comments(
    post_id: str,
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_optional_user)
):
    """Get comments for a post"""
    comments = await db.comments.find({"post_id": post_id}).sort("created_at", 1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for comment in comments:
        user = await db.users.find_one({"_id": ObjectId(comment["user_id"])})
        
        is_liked = False
        if current_user:
            like = await db.comment_likes.find_one({
                "user_id": str(current_user["_id"]),
                "comment_id": str(comment["_id"])
            })
            is_liked = like is not None
        
        result.append({
            "id": str(comment["_id"]),
            "post_id": comment["post_id"],
            "user_id": comment["user_id"],
            "username": user["username"] if user else "deleted",
            "display_name": user.get("display_name") if user else None,
            "user_profile_picture": user.get("profile_picture") if user else None,
            "is_verified": user.get("is_verified", False) if user else False,
            "content": comment["content"],
            "parent_id": comment.get("parent_id"),
            "likes_count": comment.get("likes_count", 0),
            "is_liked": is_liked,
            "created_at": comment.get("created_at", datetime.utcnow())
        })
    
    return result

@app.post("/api/comments/{comment_id}/like")
async def toggle_like_comment(comment_id: str, current_user: dict = Depends(get_current_user)):
    """Like or unlike a comment"""
    try:
        comment = await db.comments.find_one({"_id": ObjectId(comment_id)})
    except:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    user_id = str(current_user["_id"])
    
    existing = await db.comment_likes.find_one({
        "user_id": user_id,
        "comment_id": comment_id
    })
    
    if existing:
        await db.comment_likes.delete_one({"_id": existing["_id"]})
        await db.comments.update_one({"_id": ObjectId(comment_id)}, {"$inc": {"likes_count": -1}})
        is_liked = False
    else:
        await db.comment_likes.insert_one({
            "user_id": user_id,
            "comment_id": comment_id,
            "created_at": datetime.utcnow()
        })
        await db.comments.update_one({"_id": ObjectId(comment_id)}, {"$inc": {"likes_count": 1}})
        is_liked = True
    
    comment = await db.comments.find_one({"_id": ObjectId(comment_id)})
    
    return {
        "success": True,
        "is_liked": is_liked,
        "likes_count": comment.get("likes_count", 0)
    }

# =============================================================================
# Discover/Search Endpoints
# =============================================================================

@app.get("/api/discover")
async def get_discover(current_user: dict = Depends(get_optional_user)):
    """Get discover page data - trending posts, popular fandoms, top creators"""
    # Trending posts (most likes in recent time)
    trending_posts = await db.posts.find().sort([("likes_count", -1), ("created_at", -1)]).limit(10).to_list(10)
    
    # Popular fandoms
    popular_fandoms = await db.fandoms.find().sort("members_count", -1).limit(5).to_list(5)
    
    # Top creators (users with most posts)
    pipeline = [
        {"$group": {"_id": "$user_id", "post_count": {"$sum": 1}}},
        {"$sort": {"post_count": -1}},
        {"$limit": 5}
    ]
    top_creator_ids = await db.posts.aggregate(pipeline).to_list(5)
    
    top_creators = []
    for creator in top_creator_ids:
        user = await db.users.find_one({"_id": ObjectId(creator["_id"])})
        if user:
            followers_count = await db.follows.count_documents({"following_id": creator["_id"]})
            top_creators.append({
                "id": str(user["_id"]),
                "username": user["username"],
                "display_name": user.get("display_name"),
                "profile_picture": user.get("profile_picture"),
                "is_verified": user.get("is_verified", False),
                "posts_count": creator["post_count"],
                "followers_count": followers_count
            })
    
    user_joined = current_user.get("joined_fandoms", []) if current_user else []
    
    # Format trending posts
    formatted_posts = []
    for post in trending_posts:
        user = await db.users.find_one({"_id": ObjectId(post["user_id"])})
        fandom = await db.fandoms.find_one({"_id": ObjectId(post["fandom_id"])})
        
        is_liked = False
        if current_user:
            like = await db.likes.find_one({
                "user_id": str(current_user["_id"]),
                "post_id": str(post["_id"])
            })
            is_liked = like is not None
        
        formatted_posts.append({
            "id": str(post["_id"]),
            "user_id": post["user_id"],
            "username": user["username"] if user else "deleted",
            "display_name": user.get("display_name") if user else None,
            "user_profile_picture": user.get("profile_picture") if user else None,
            "is_verified": user.get("is_verified", False) if user else False,
            "content": post["content"],
            "image": post.get("image"),
            "fandom_id": post["fandom_id"],
            "fandom_name": fandom["name"] if fandom else "Unknown",
            "fandom_slug": fandom["slug"] if fandom else "unknown",
            "post_type": post.get("post_type", "text"),
            "hashtags": post.get("hashtags", []),
            "likes_count": post.get("likes_count", 0),
            "comments_count": post.get("comments_count", 0),
            "is_liked": is_liked,
            "created_at": post.get("created_at", datetime.utcnow())
        })
    
    return {
        "trending_posts": formatted_posts,
        "popular_fandoms": [{
            "id": str(f["_id"]),
            "name": f["name"],
            "slug": f["slug"],
            "description": f["description"],
            "icon": f["icon"],
            "color": f["color"],
            "members_count": f.get("members_count", 0),
            "is_joined": str(f["_id"]) in user_joined
        } for f in popular_fandoms],
        "top_creators": top_creators
    }

@app.get("/api/search")
async def search(
    q: str,
    type: str = "all",  # all, posts, users, fandoms
    skip: int = 0,
    limit: int = 20,
    current_user: dict = Depends(get_optional_user)
):
    """Search across posts, users, and fandoms"""
    results = {"posts": [], "users": [], "fandoms": []}
    
    if type in ["all", "posts"]:
        posts = await db.posts.find({
            "$or": [
                {"content": {"$regex": q, "$options": "i"}},
                {"hashtags": {"$in": [q.lower(), f"#{q.lower()}"]}}
            ]
        }).sort("created_at", -1).limit(limit).to_list(limit)
        
        for post in posts:
            user = await db.users.find_one({"_id": ObjectId(post["user_id"])})
            fandom = await db.fandoms.find_one({"_id": ObjectId(post["fandom_id"])})
            
            results["posts"].append({
                "id": str(post["_id"]),
                "user_id": post["user_id"],
                "username": user["username"] if user else "deleted",
                "display_name": user.get("display_name") if user else None,
                "content": post["content"][:100],
                "fandom_name": fandom["name"] if fandom else "Unknown",
                "likes_count": post.get("likes_count", 0)
            })
    
    if type in ["all", "users"]:
        users = await db.users.find({
            "$or": [
                {"username": {"$regex": q, "$options": "i"}},
                {"display_name": {"$regex": q, "$options": "i"}}
            ]
        }).limit(limit).to_list(limit)
        
        for user in users:
            results["users"].append({
                "id": str(user["_id"]),
                "username": user["username"],
                "display_name": user.get("display_name"),
                "profile_picture": user.get("profile_picture"),
                "is_verified": user.get("is_verified", False)
            })
    
    if type in ["all", "fandoms"]:
        fandoms = await db.fandoms.find({
            "$or": [
                {"name": {"$regex": q, "$options": "i"}},
                {"description": {"$regex": q, "$options": "i"}}
            ]
        }).limit(limit).to_list(limit)
        
        user_joined = current_user.get("joined_fandoms", []) if current_user else []
        
        for fandom in fandoms:
            results["fandoms"].append({
                "id": str(fandom["_id"]),
                "name": fandom["name"],
                "slug": fandom["slug"],
                "icon": fandom["icon"],
                "color": fandom["color"],
                "members_count": fandom.get("members_count", 0),
                "is_joined": str(fandom["_id"]) in user_joined
            })
    
    return results

# =============================================================================
# Admin Endpoints
# =============================================================================

@app.get("/api/admin/users")
async def admin_get_users(skip: int = 0, limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get all users (admin/owner only)"""
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    users = await db.users.find().skip(skip).limit(limit).to_list(limit)
    
    result = []
    for user in users:
        result.append({
            "id": str(user["_id"]),
            "email": user["email"],
            "username": user["username"],
            "display_name": user.get("display_name"),
            "role": user.get("role", "user"),
            "is_verified": user.get("is_verified", False),
            "created_at": user.get("created_at", datetime.utcnow())
        })
    
    return result

@app.put("/api/admin/users/{user_id}/role")
async def admin_update_user_role(
    user_id: str,
    role: str,
    current_user: dict = Depends(get_current_user)
):
    """Update user role (owner only)"""
    if current_user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Only owner can change roles")
    
    if role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    try:
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"role": role}}
        )
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"success": True}

@app.put("/api/admin/users/{user_id}/verify")
async def admin_verify_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Verify a user account (admin/owner only)"""
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_status = not user.get("is_verified", False)
    
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_verified": new_status}}
    )
    
    return {"success": True, "is_verified": new_status}

@app.delete("/api/admin/users/{user_id}")
async def admin_ban_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Ban/delete a user (admin/owner only)"""
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Cannot ban owner
    if user.get("role") == "owner":
        raise HTTPException(status_code=403, detail="Cannot ban the owner")
    
    # Delete user's data
    await db.users.delete_one({"_id": ObjectId(user_id)})
    await db.posts.delete_many({"user_id": user_id})
    await db.comments.delete_many({"user_id": user_id})
    await db.likes.delete_many({"user_id": user_id})
    await db.follows.delete_many({"$or": [{"follower_id": user_id}, {"following_id": user_id}]})
    
    return {"success": True}

# =============================================================================
# Health Check
# =============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Hearties Social API",
        "version": "1.0.0"
    }

# =============================================================================
# Report Endpoints
# =============================================================================

@app.post("/api/reports/post/{post_id}")
async def report_post(post_id: str, report_data: ReportCreate, current_user: dict = Depends(get_current_user)):
    """Report a post"""
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
    except:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Check if already reported by this user
    existing = await db.reports.find_one({
        "reporter_id": str(current_user["_id"]),
        "target_type": "post",
        "target_id": post_id
    })
    
    if existing:
        raise HTTPException(status_code=400, detail="You have already reported this post")
    
    report_doc = {
        "reporter_id": str(current_user["_id"]),
        "target_type": "post",
        "target_id": post_id,
        "target_user_id": post["user_id"],
        "reason": report_data.reason,
        "report_type": report_data.report_type,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    result = await db.reports.insert_one(report_doc)
    
    return {
        "success": True,
        "id": str(result.inserted_id),
        "message": "Report submitted successfully"
    }

@app.post("/api/reports/user/{user_id}")
async def report_user(user_id: str, report_data: ReportCreate, current_user: dict = Depends(get_current_user)):
    """Report a user"""
    if str(current_user["_id"]) == user_id:
        raise HTTPException(status_code=400, detail="Cannot report yourself")
    
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if already reported by this user
    existing = await db.reports.find_one({
        "reporter_id": str(current_user["_id"]),
        "target_type": "user",
        "target_id": user_id
    })
    
    if existing:
        raise HTTPException(status_code=400, detail="You have already reported this user")
    
    report_doc = {
        "reporter_id": str(current_user["_id"]),
        "target_type": "user",
        "target_id": user_id,
        "target_user_id": user_id,
        "reason": report_data.reason,
        "report_type": report_data.report_type,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    result = await db.reports.insert_one(report_doc)
    
    return {
        "success": True,
        "id": str(result.inserted_id),
        "message": "Report submitted successfully"
    }

@app.post("/api/reports/comment/{comment_id}")
async def report_comment(comment_id: str, report_data: ReportCreate, current_user: dict = Depends(get_current_user)):
    """Report a comment"""
    try:
        comment = await db.comments.find_one({"_id": ObjectId(comment_id)})
    except:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    existing = await db.reports.find_one({
        "reporter_id": str(current_user["_id"]),
        "target_type": "comment",
        "target_id": comment_id
    })
    
    if existing:
        raise HTTPException(status_code=400, detail="You have already reported this comment")
    
    report_doc = {
        "reporter_id": str(current_user["_id"]),
        "target_type": "comment",
        "target_id": comment_id,
        "target_user_id": comment["user_id"],
        "reason": report_data.reason,
        "report_type": report_data.report_type,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    result = await db.reports.insert_one(report_doc)
    
    return {
        "success": True,
        "id": str(result.inserted_id),
        "message": "Report submitted successfully"
    }

# =============================================================================
# Block Endpoints
# =============================================================================

@app.post("/api/users/{user_id}/block")
async def toggle_block_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Block or unblock a user"""
    if str(current_user["_id"]) == user_id:
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    
    try:
        target_user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    blocker_id = str(current_user["_id"])
    
    existing = await db.blocks.find_one({
        "blocker_id": blocker_id,
        "blocked_id": user_id
    })
    
    if existing:
        # Unblock
        await db.blocks.delete_one({"_id": existing["_id"]})
        is_blocked = False
    else:
        # Block
        await db.blocks.insert_one({
            "blocker_id": blocker_id,
            "blocked_id": user_id,
            "created_at": datetime.utcnow()
        })
        is_blocked = True
        
        # Also unfollow if following
        await db.follows.delete_one({
            "follower_id": blocker_id,
            "following_id": user_id
        })
        await db.follows.delete_one({
            "follower_id": user_id,
            "following_id": blocker_id
        })
    
    return {
        "success": True,
        "is_blocked": is_blocked
    }

@app.get("/api/users/{user_id}/is-blocked")
async def check_is_blocked(user_id: str, current_user: dict = Depends(get_current_user)):
    """Check if current user has blocked target user"""
    existing = await db.blocks.find_one({
        "blocker_id": str(current_user["_id"]),
        "blocked_id": user_id
    })
    return {"is_blocked": existing is not None}

# =============================================================================
# Admin Reports Management
# =============================================================================

@app.get("/api/admin/reports")
async def admin_get_reports(
    status: str = "pending",
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get all reports (admin/owner only)"""
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    query = {}
    if status != "all":
        query["status"] = status
    
    reports = await db.reports.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for report in reports:
        reporter = await db.users.find_one({"_id": ObjectId(report["reporter_id"])})
        
        # Get target info based on type
        target_info = None
        if report["target_type"] == "post":
            target = await db.posts.find_one({"_id": ObjectId(report["target_id"])})
            if target:
                target_info = {"content": target.get("content", "")[:100]}
        elif report["target_type"] == "user":
            target = await db.users.find_one({"_id": ObjectId(report["target_id"])})
            if target:
                target_info = {"username": target["username"]}
        elif report["target_type"] == "comment":
            target = await db.comments.find_one({"_id": ObjectId(report["target_id"])})
            if target:
                target_info = {"content": target.get("content", "")[:100]}
        
        result.append({
            "id": str(report["_id"]),
            "reporter": {
                "id": str(reporter["_id"]) if reporter else None,
                "username": reporter["username"] if reporter else "deleted"
            },
            "target_type": report["target_type"],
            "target_id": report["target_id"],
            "target_info": target_info,
            "reason": report["reason"],
            "report_type": report["report_type"],
            "status": report["status"],
            "created_at": report.get("created_at", datetime.utcnow())
        })
    
    return result

@app.put("/api/admin/reports/{report_id}")
async def admin_update_report(
    report_id: str,
    status: str,
    current_user: dict = Depends(get_current_user)
):
    """Update report status (admin/owner only)"""
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if status not in ["pending", "reviewed", "resolved", "dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    try:
        result = await db.reports.update_one(
            {"_id": ObjectId(report_id)},
            {"$set": {"status": status, "reviewed_by": str(current_user["_id"]), "reviewed_at": datetime.utcnow()}}
        )
    except:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {"success": True}

@app.get("/api/admin/posts")
async def admin_get_posts(
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get all posts for admin management"""
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    posts = await db.posts.find().sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for post in posts:
        user = await db.users.find_one({"_id": ObjectId(post["user_id"])})
        fandom = await db.fandoms.find_one({"_id": ObjectId(post["fandom_id"])})
        
        # Count reports for this post
        report_count = await db.reports.count_documents({"target_type": "post", "target_id": str(post["_id"])})
        
        result.append({
            "id": str(post["_id"]),
            "user_id": post["user_id"],
            "username": user["username"] if user else "deleted",
            "display_name": user.get("display_name") if user else None,
            "content": post["content"],
            "image": post.get("image"),
            "fandom_name": fandom["name"] if fandom else "Unknown",
            "likes_count": post.get("likes_count", 0),
            "comments_count": post.get("comments_count", 0),
            "report_count": report_count,
            "created_at": post.get("created_at", datetime.utcnow())
        })
    
    return result

@app.get("/api/admin/stats")
async def admin_get_stats(current_user: dict = Depends(get_current_user)):
    """Get admin dashboard statistics"""
    print(f"Admin stats - User role: {current_user.get('role')}, Username: {current_user.get('username')}")
    if current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail=f"Not authorized. Role: {current_user.get('role')}")
    
    total_users = await db.users.count_documents({})
    total_posts = await db.posts.count_documents({})
    total_comments = await db.comments.count_documents({})
    total_fandoms = await db.fandoms.count_documents({})
    pending_reports = await db.reports.count_documents({"status": "pending"})
    
    # Users by role
    admins_count = await db.users.count_documents({"role": "admin"})
    owners_count = await db.users.count_documents({"role": "owner"})
    
    return {
        "total_users": total_users,
        "total_posts": total_posts,
        "total_comments": total_comments,
        "total_fandoms": total_fandoms,
        "pending_reports": pending_reports,
        "admins_count": admins_count,
        "owners_count": owners_count
    }

# =============================================================================
# Stories Endpoints
# =============================================================================

@app.post("/api/stories")
async def create_story(story_data: StoryCreate, current_user: dict = Depends(get_current_user)):
    """Create a new story (expires in 24 hours)"""
    story_doc = {
        "user_id": str(current_user["_id"]),
        "media_type": story_data.media_type,
        "media_url": story_data.media_url,
        "media_base64": story_data.media_base64,
        "caption": story_data.caption,
        "views": [],
        "views_count": 0,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(hours=24)
    }
    
    result = await db.stories.insert_one(story_doc)
    
    return {
        "success": True,
        "id": str(result.inserted_id),
        "message": "Story created successfully"
    }

@app.get("/api/stories")
async def get_stories(current_user: dict = Depends(get_current_user)):
    """Get stories from followed users and self"""
    user_id = str(current_user["_id"])
    
    # Get users I follow
    follows = await db.follows.find({"follower_id": user_id}).to_list(500)
    following_ids = [f["following_id"] for f in follows]
    following_ids.append(user_id)  # Include own stories
    
    # Get active stories (not expired)
    now = datetime.utcnow()
    stories = await db.stories.find({
        "user_id": {"$in": following_ids},
        "expires_at": {"$gt": now}
    }).sort("created_at", -1).to_list(100)
    
    # Group stories by user
    users_stories = {}
    for story in stories:
        story_user_id = story["user_id"]
        if story_user_id not in users_stories:
            user = await db.users.find_one({"_id": ObjectId(story_user_id)})
            users_stories[story_user_id] = {
                "user": {
                    "id": story_user_id,
                    "username": user["username"] if user else "deleted",
                    "display_name": user.get("display_name") if user else None,
                    "profile_picture": user.get("profile_picture") if user else None
                },
                "stories": [],
                "has_unviewed": False
            }
        
        is_viewed = user_id in story.get("views", [])
        if not is_viewed:
            users_stories[story_user_id]["has_unviewed"] = True
            
        users_stories[story_user_id]["stories"].append({
            "id": str(story["_id"]),
            "media_type": story["media_type"],
            "media_url": story.get("media_url"),
            "media_base64": story.get("media_base64"),
            "caption": story.get("caption"),
            "views_count": story.get("views_count", 0),
            "created_at": story["created_at"],
            "expires_at": story["expires_at"],
            "is_viewed": is_viewed
        })
    
    # Sort: own stories first, then unviewed, then viewed
    result = []
    for uid, data in users_stories.items():
        if uid == user_id:
            result.insert(0, data)
        elif data["has_unviewed"]:
            result.append(data)
        else:
            result.append(data)
    
    return result

@app.post("/api/stories/{story_id}/view")
async def view_story(story_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a story as viewed"""
    user_id = str(current_user["_id"])
    
    try:
        story = await db.stories.find_one({"_id": ObjectId(story_id)})
    except:
        raise HTTPException(status_code=404, detail="Story not found")
    
    if not story:
        raise HTTPException(status_code=404, detail="Story not found")
    
    # Add to views if not already viewed
    if user_id not in story.get("views", []):
        await db.stories.update_one(
            {"_id": ObjectId(story_id)},
            {
                "$addToSet": {"views": user_id},
                "$inc": {"views_count": 1}
            }
        )
    
    return {"success": True}

@app.delete("/api/stories/{story_id}")
async def delete_story(story_id: str, current_user: dict = Depends(get_current_user)):
    """Delete own story"""
    user_id = str(current_user["_id"])
    
    try:
        story = await db.stories.find_one({"_id": ObjectId(story_id)})
    except:
        raise HTTPException(status_code=404, detail="Story not found")
    
    if not story:
        raise HTTPException(status_code=404, detail="Story not found")
    
    if story["user_id"] != user_id and current_user.get("role") not in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.stories.delete_one({"_id": ObjectId(story_id)})
    
    return {"success": True}

# =============================================================================
# Private Messages Endpoints
# =============================================================================

@app.get("/api/conversations")
async def get_conversations(current_user: dict = Depends(get_current_user)):
    """Get all conversations for current user"""
    user_id = str(current_user["_id"])
    
    # Find all conversations where user is a participant
    conversations = await db.conversations.find({
        "participants": user_id
    }).sort("updated_at", -1).to_list(50)
    
    result = []
    for conv in conversations:
        # Get the other participant
        other_id = [p for p in conv["participants"] if p != user_id][0]
        other_user = await db.users.find_one({"_id": ObjectId(other_id)})
        
        # Get last message
        last_msg = await db.messages.find_one(
            {"conversation_id": str(conv["_id"])},
            sort=[("created_at", -1)]
        )
        
        # Count unread messages
        unread = await db.messages.count_documents({
            "conversation_id": str(conv["_id"]),
            "sender_id": {"$ne": user_id},
            "is_read": False
        })
        
        result.append({
            "id": str(conv["_id"]),
            "participant": {
                "id": other_id,
                "username": other_user["username"] if other_user else "deleted",
                "display_name": other_user.get("display_name") if other_user else None,
                "profile_picture": other_user.get("profile_picture") if other_user else None
            },
            "last_message": {
                "content": last_msg["content"][:50] if last_msg else None,
                "created_at": last_msg["created_at"] if last_msg else None,
                "is_mine": last_msg["sender_id"] == user_id if last_msg else False
            } if last_msg else None,
            "unread_count": unread,
            "updated_at": conv.get("updated_at", conv.get("created_at"))
        })
    
    return result

@app.post("/api/conversations/{user_id}")
async def create_or_get_conversation(user_id: str, current_user: dict = Depends(get_current_user)):
    """Create or get existing conversation with a user"""
    my_id = str(current_user["_id"])
    
    if my_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot message yourself")
    
    # Check if other user exists
    try:
        other_user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if blocked
    is_blocked = await db.blocks.find_one({
        "$or": [
            {"blocker_id": my_id, "blocked_id": user_id},
            {"blocker_id": user_id, "blocked_id": my_id}
        ]
    })
    
    if is_blocked:
        raise HTTPException(status_code=403, detail="Cannot message this user")
    
    # Find existing conversation
    participants = sorted([my_id, user_id])
    existing = await db.conversations.find_one({
        "participants": {"$all": participants}
    })
    
    if existing:
        return {
            "id": str(existing["_id"]),
            "is_new": False
        }
    
    # Create new conversation
    conv_doc = {
        "participants": participants,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await db.conversations.insert_one(conv_doc)
    
    return {
        "id": str(result.inserted_id),
        "is_new": True
    }

@app.get("/api/conversations/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get messages in a conversation"""
    user_id = str(current_user["_id"])
    
    # Verify user is participant
    try:
        conv = await db.conversations.find_one({"_id": ObjectId(conversation_id)})
    except:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    if not conv or user_id not in conv["participants"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get messages
    messages = await db.messages.find({
        "conversation_id": conversation_id
    }).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    # Mark messages as read
    await db.messages.update_many(
        {
            "conversation_id": conversation_id,
            "sender_id": {"$ne": user_id},
            "is_read": False
        },
        {"$set": {"is_read": True}}
    )
    
    return [{
        "id": str(msg["_id"]),
        "conversation_id": msg["conversation_id"],
        "sender_id": msg["sender_id"],
        "content": msg["content"],
        "media_url": msg.get("media_url"),
        "media_type": msg.get("media_type"),
        "is_read": msg.get("is_read", False),
        "created_at": msg["created_at"],
        "is_mine": msg["sender_id"] == user_id
    } for msg in reversed(messages)]

@app.post("/api/conversations/{conversation_id}/messages")
async def send_message(
    conversation_id: str,
    message_data: MessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a message in a conversation"""
    user_id = str(current_user["_id"])
    
    # Verify user is participant
    try:
        conv = await db.conversations.find_one({"_id": ObjectId(conversation_id)})
    except:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    if not conv or user_id not in conv["participants"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check if blocked
    other_id = [p for p in conv["participants"] if p != user_id][0]
    is_blocked = await db.blocks.find_one({
        "$or": [
            {"blocker_id": user_id, "blocked_id": other_id},
            {"blocker_id": other_id, "blocked_id": user_id}
        ]
    })
    
    if is_blocked:
        raise HTTPException(status_code=403, detail="Cannot message this user")
    
    # Create message
    msg_doc = {
        "conversation_id": conversation_id,
        "sender_id": user_id,
        "content": message_data.content,
        "media_base64": message_data.media_base64,
        "media_type": message_data.media_type,
        "is_read": False,
        "created_at": datetime.utcnow()
    }
    
    result = await db.messages.insert_one(msg_doc)
    
    # Update conversation timestamp
    await db.conversations.update_one(
        {"_id": ObjectId(conversation_id)},
        {"$set": {"updated_at": datetime.utcnow()}}
    )
    
    # Create notification for recipient
    await db.notifications.insert_one({
        "user_id": other_id,
        "type": "message",
        "from_user_id": user_id,
        "content": f"New message from {current_user['username']}",
        "reference_id": conversation_id,
        "is_read": False,
        "created_at": datetime.utcnow()
    })
    
    return {
        "success": True,
        "id": str(result.inserted_id),
        "message": {
            "id": str(result.inserted_id),
            "content": message_data.content,
            "created_at": datetime.utcnow(),
            "is_mine": True
        }
    }

# =============================================================================
# Notifications Endpoints
# =============================================================================

@app.get("/api/notifications")
async def get_notifications(
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get notifications for current user"""
    user_id = str(current_user["_id"])
    
    notifications = await db.notifications.find({
        "user_id": user_id
    }).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for notif in notifications:
        from_user = None
        if notif.get("from_user_id"):
            from_user_doc = await db.users.find_one({"_id": ObjectId(notif["from_user_id"])})
            if from_user_doc:
                from_user = {
                    "id": str(from_user_doc["_id"]),
                    "username": from_user_doc["username"],
                    "profile_picture": from_user_doc.get("profile_picture")
                }
        
        result.append({
            "id": str(notif["_id"]),
            "type": notif["type"],
            "content": notif["content"],
            "from_user": from_user,
            "reference_id": notif.get("reference_id"),
            "is_read": notif.get("is_read", False),
            "created_at": notif["created_at"]
        })
    
    return result

@app.get("/api/notifications/unread-count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    """Get count of unread notifications"""
    user_id = str(current_user["_id"])
    
    count = await db.notifications.count_documents({
        "user_id": user_id,
        "is_read": False
    })
    
    return {"unread_count": count}

@app.post("/api/notifications/mark-read")
async def mark_notifications_read(current_user: dict = Depends(get_current_user)):
    """Mark all notifications as read"""
    user_id = str(current_user["_id"])
    
    await db.notifications.update_many(
        {"user_id": user_id, "is_read": False},
        {"$set": {"is_read": True}}
    )
    
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
