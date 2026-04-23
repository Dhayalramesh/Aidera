from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from .db import Base, engine, SessionLocal
from .models import User, Customer
from pydantic import BaseModel
import hashlib
from jose import jwt
from fastapi.middleware.cors import CORSMiddleware

SECRET = "secret123"

app = FastAPI()

# ✅ CORS (required for frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Create tables
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
def create_token(email):
    return jwt.encode({"email": email}, SECRET, algorithm="HS256")

def verify_token(token):
    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
        return data["email"]
    except:
        return None

# ---------- AUTH ----------

@app.post("/register")
def register(user: UserIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()

    if existing:
        raise HTTPException(status_code=400, detail="User exists")

    new_user = User(
        email=user.email,
        password=hash_pw(user.password)
    )

    db.add(new_user)
    db.commit()

    return {"msg": "registered"}


@app.post("/login")
def login(user: UserIn, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if db_user.password != hash_pw(user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user.email)

    return {"token": token}

# ---------- CUSTOMERS ----------

@app.get("/customers")
def get_customers(token: str, db: Session = Depends(get_db)):
    email = verify_token(token)

    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return db.query(Customer).all()


@app.post("/customers")
def add_customer(data: CustomerIn, token: str, db: Session = Depends(get_db)):
    email = verify_token(token)

    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    new_customer = Customer(
        name=data.name,
        phone=data.phone,
        address=data.address,
        area=data.area
    )

    db.add(new_customer)
    db.commit()

    return {"msg": "added"}


@app.delete("/customers/{id}")
def delete_customer(id: int, token: str, db: Session = Depends(get_db)):
    email = verify_token(token)

    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    customer = db.query(Customer).filter(Customer.id == id).first()

    if not customer:
        raise HTTPException(status_code=404, detail="Not found")

    db.delete(customer)
    db.commit()

    return {"msg": "deleted"}