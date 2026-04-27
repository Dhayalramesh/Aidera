from fastapi import FastAPI, HTTPException, Depends, Header
from sqlalchemy.orm import Session
from .db import Base, engine, SessionLocal
from .models import User, Customer
from pydantic import BaseModel
import hashlib
from jose import jwt, JWTError
from fastapi.middleware.cors import CORSMiddleware

# ---------- CONFIG ----------
SECRET = "secret123"
ALGO = "HS256"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# ---------- DB ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- SCHEMAS ----------
class UserIn(BaseModel):
    email: str
    password: str

class CustomerIn(BaseModel):
    name: str
    phone: str
    address: str
    area: str

# ---------- HASH ----------
def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------- TOKEN ----------
def create_token(email: str):
    return jwt.encode({"email": email}, SECRET, algorithm=ALGO)

def verify_token(authorization: str = Header(None)):
    if not authorization:
        return None

    try:
        token = authorization.split(" ")[1]
        data = jwt.decode(token, SECRET, algorithms=[ALGO])
        return data.get("email")
    except:
        return None

# ---------- AUTH ----------
@app.post("/register")
def register(user: UserIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(400, "User exists")

    db.add(User(email=user.email, password=hash_pw(user.password)))
    db.commit()

    return {"msg": "registered"}


@app.post("/login")
def login(user: UserIn, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == user.email).first()

    if not u or u.password != hash_pw(user.password):
        raise HTTPException(401, "Invalid credentials")

    return {"token": create_token(user.email)}

# ---------- CUSTOMERS ----------
@app.get("/customers")
def get_customers(
    db: Session = Depends(get_db),
    email: str = Depends(verify_token)
):
    if not email:
        raise HTTPException(401, "Invalid token")

    return db.query(Customer).filter(Customer.user_email == email).all()


@app.post("/customers")
def add_customer(
    data: CustomerIn,
    db: Session = Depends(get_db),
    email: str = Depends(verify_token)
):
    if not email:
        raise HTTPException(401, "Invalid token")

    c = Customer(
        name=data.name,
        phone=data.phone,
        address=data.address,
        area=data.area,
        user_email=email
    )

    db.add(c)
    db.commit()

    return {"msg": "added"}


@app.delete("/customers/{id}")
def delete_customer(
    id: int,
    db: Session = Depends(get_db),
    email: str = Depends(verify_token)
):
    if not email:
        raise HTTPException(401, "Invalid token")

    c = db.query(Customer).filter(
        Customer.id == id,
        Customer.user_email == email
    ).first()

    if not c:
        raise HTTPException(404, "Not found")

    db.delete(c)
    db.commit()

    return {"msg": "deleted"}