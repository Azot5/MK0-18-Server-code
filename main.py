#test MK 0-1

import random
import hashlib
import configparser
from xml.etree import ElementTree as ET
from tqdm import tqdm
import sqlite3
from config_reader import config
from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.security import OAuth2PasswordBearer
from fastapi import status

templates = Jinja2Templates(directory="templates")

SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM
USER_DATABASE_URL = config.USER_DATABASE_URL
ADMIN_DATABASE_URL = config.ADMIN_DATABASE_URL
QUEUE_DATABASE_URL = config.QUEUE_DATABASE_URL
VACCINE_DATABASE_URL = config.VACCINE_DATABASE_URL

SERVER_MAINTENANCE_MODE = False

Base = declarative_base()

user_engine = create_engine(USER_DATABASE_URL, connect_args={"check_same_thread": False})
admin_engine = create_engine(ADMIN_DATABASE_URL, connect_args={"check_same_thread": False})
queue_engine = create_engine(QUEUE_DATABASE_URL, connect_args={"check_same_thread": False})
vaccine_engine = create_engine(VACCINE_DATABASE_URL, connect_args={"check_same_thread": False})


UserSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=user_engine)
AdminSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=admin_engine)
QueueSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=queue_engine)
VaccineSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=vaccine_engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    vaccine_info = Column(String, nullable=True)  # Add this line

class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Queue(Base):
    __tablename__ = "queue"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)

class ActionLog(Base):
    __tablename__ = "action_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    username = Column(String)
    action = Column(String)
    response = Column(String)

class Vaccine(Base):
    __tablename__ = "vaccines"
    id = Column(Integer, primary_key=True, index=True)
    vaccine_name = Column(String, unique=True, index=True)
    date_added = Column(String)
    added_by = Column(String)
    is_active = Column(Integer)  # 1 for active, 0 for inactive
    last_modified = Column(String)
    modified_by = Column(String)

Base.metadata.create_all(bind=user_engine)
Base.metadata.create_all(bind=admin_engine)
Base.metadata.create_all(bind=queue_engine)
Base.metadata.create_all(bind=vaccine_engine)

def get_user_db():
    db = UserSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_admin_db():
    db = AdminSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_queue_db():
    db = QueueSessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def get_vaccine_db():
    db = VaccineSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def authenticate_admin(db: Session, username: str, password: str):
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or not verify_password(password, admin.hashed_password):
        return False
    return admin

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def log_action(db: Session, username: str, action: str, response: str):
    log_entry = ActionLog(
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        username=username,
        action=action,
        response=response
    )
    db.add(log_entry)
    db.commit()

def generate_and_hash_code():
    code = str(random.randint(100, 999))
    hashed_code = hashlib.sha256((SECRET_KEY + code).encode('utf-8')).hexdigest()
    print(f"Numeric security code: {code}, Hashed code: {hashed_code}")
    return code, hashed_code

generated_code, hashed_code = generate_and_hash_code()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/healthcheck")
async def healthcheck():
    return {"status": "ok"}

@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    admin_key: str = Form(None),
    db: Session = Depends(get_user_db)
):
    if admin_key and hashlib.sha256((SECRET_KEY + admin_key).encode('utf-8')).hexdigest() == hashed_code:
        new_admin = Admin(username=username, hashed_password=get_password_hash(password))
        db.add(new_admin)
        db.commit()
        log_action(db, username, "register", "Admin registration successful")
        return RedirectResponse(url="/", status_code=303)

    if db.query(User).filter(User.username == username).first():
        log_action(db, username, "register", "Username already registered")
        error_message = "Username already registered"
        return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

    if db.query(User).filter(User.email == email).first():
        log_action(db, username, "register", "Email already registered")
        error_message = "Email already registered"
        return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

    new_user = User(username=username, email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    log_action(db, username, "register", "Registration successful")

    return RedirectResponse(url="/", status_code=303)

@app.post("/token")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_user_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token({"sub": user.username})
    
    return JSONResponse(content={"access_token": access_token})

@app.get("/welcome", response_class=HTMLResponse)
async def welcome_page(request: Request, username: str = "Guest"):
    return templates.TemplateResponse("welcome.html", {"request": request, "username": username})

@app.get("/queue/position")
async def get_user_position(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_queue_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        queue_entry = db.query(Queue).filter(Queue.name == username).first()
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        return {"id": queue_entry.id, "name": queue_entry.name}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/queue/add")
async def add_to_queue(
    request: Request,  
    db: Session = Depends(get_queue_db)
):
    try:
        authorization_header = request.headers.get("Authorization")
        if authorization_header is None:
            raise HTTPException(status_code=401, detail="Authorization header is missing")
        
        token_parts = authorization_header.split(" ")
        if len(token_parts) != 2 or token_parts[0] != "Bearer":
            raise HTTPException(status_code=400, detail="Malformed Authorization header")
        
        token = token_parts[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        new_queue_entry = Queue(name=username)
        db.add(new_queue_entry)
        db.commit()
        db.refresh(new_queue_entry)

        return {"id": new_queue_entry.id, "name": new_queue_entry.name}
    
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/queue/remove")
async def remove_from_queue(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_queue_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        queue_entry = db.query(Queue).filter(Queue.name == username).first()
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        db.delete(queue_entry)
        db.commit()

        remaining_entries = db.query(Queue).filter(Queue.id > queue_entry.id).all()
        for entry in remaining_entries:
            entry.id -= 1
        db.commit()

        return {"message": "User removed", "id": queue_entry.id}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/admin/register")
async def register_admin(username: str = Form(...), password: str = Form(...), admin_key: str = Form(...), db: Session = Depends(get_admin_db)):
    
    print(admin_key)
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    if db.query(Admin).filter(Admin.username == username).first():
        raise HTTPException(status_code=400, detail="Admin username already registered")
    new_admin = Admin(username=username, hashed_password=get_password_hash(password))
    db.add(new_admin)
    db.commit()
    return {"message": "Admin registered successfully"}

@app.post("/admin/token")
async def login_admin(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_admin_db)
):

    admin = authenticate_admin(db, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(
            status_code=401,
            detail="Невірне ім'я користувача або пароль",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_access_token({"sub": admin.username})
    
    log_action(db, admin.username, "admin_login", "Successful admin login")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": admin.username
    }

@app.get("/admin/queue/user/{queue_id}")
async def get_user_by_queue_id(queue_id: int, admin_key: str = Form(...), db: Session = Depends(get_queue_db)):
    
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    user_entry = db.query(Queue).filter(Queue.id == queue_id).first()
    if not user_entry:
        raise HTTPException(status_code=404, detail="User not found in queue")
    return {"id": user_entry.id, "name": user_entry.name}

@app.post("/admin/queue/remove_first")
async def admin_remove_first(
    request: Request,
    vaccine_name: str = Form(...),
    db_queue: Session = Depends(get_queue_db),
    db_user: Session = Depends(get_user_db),
    db_admin: Session = Depends(get_admin_db),
    token: str = Depends(oauth2_scheme)  # Очікуємо токен у заголовку Authorization
):
    # Декодуємо токен для отримання username
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401_1, detail="Invalid token")

    # Перевіряємо, чи адмін існує (можливо, вам потрібна додаткова перевірка)
    admin = db_admin.query(Admin).filter(Admin.username == username).first()
    if not admin:
        raise HTTPException(
            status_code=401,
            detail="Admin not found",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Get first in queue
    first_entry = db_queue.query(Queue).order_by(Queue.id.asc()).first()
    if not first_entry:
        raise HTTPException(status_code=400, detail="Queue is empty")

    # Update user's vaccine info
    try:
        user = db_user.query(User).filter(User.username == first_entry.name).first()
        if user:
            current_time = datetime.now().strftime("%Y.%m.%d %H:%M:%S")
            vaccine_info = f"{vaccine_name} {current_time}"

            # Initialize vaccine_info if it's None
            if not hasattr(user, 'vaccine_info') or user.vaccine_info is None:
                user.vaccine_info = vaccine_info
            else:
                user.vaccine_info = f"{user.vaccine_info}, {vaccine_info}"

            db_user.commit()
        else:
            print(f"User {first_entry.name} not found in user database.")
    except Exception as e:
        print(f"Error updating vaccine info: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to update vaccine information"
        )

    # Remove first entry from queue
    db_queue.delete(first_entry)
    db_queue.commit()

    # Renumber remaining entries
    remaining_entries = db_queue.query(Queue).order_by(Queue.id).all()
    for index, entry in enumerate(remaining_entries, start=1):
        entry.id = index
    db_queue.commit()

    return {
        "message": "First entry removed and user vaccinated",
        "vaccinated_user": first_entry.name,
        "vaccine_info": vaccine_info,
        "updated_queue": [{"id": entry.id, "name": entry.name} for entry in remaining_entries]
    }

    # Видалення першого запису з черги
    db_queue.delete(first_entry)
    db_queue.commit()

    # Перенумерація решти записів у черзі
    remaining_entries = db_queue.query(Queue).filter(Queue.id > 1).order_by(Queue.id).all()
    for index, entry in enumerate(remaining_entries, start=1):
        entry.id = index
    db_queue.commit()

    return {
        "message": "First entry removed and user vaccinated",
        "vaccinated_user": first_entry.name,
        "vaccine_info": vaccine_info,
        "updated_queue": [{"id": entry.id, "name": entry.name} for entry in remaining_entries]
    }

@app.post("/admin/queue/clear")
async def clear_queue(admin_key: str = Form(...), db: Session = Depends(get_queue_db)):
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    db.query(Queue).delete()
    db.commit()
    
    return {"message": "Queue cleared successfully"}

@app.post("/admin/delete")
async def delete_admin(username: str = Form(...), admin_key: str = Form(...), db: Session = Depends(get_admin_db)):
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    db.delete(admin)
    db.commit()

    return {"message": f"Admin '{username}' deleted successfully"}

@app.get("/edit-account-home", response_class=HTMLResponse)
async def edit_account_home(request: Request):
    return templates.TemplateResponse("edit_account.html", {"request": request})

@app.get("/edit-account-username", response_class=HTMLResponse)
async def edit_account_username(request: Request):
    return templates.TemplateResponse("edit_account_username.html", {"request": request})

@app.get("/edit-account-password", response_class=HTMLResponse)
async def edit_account_password(request: Request):
    return templates.TemplateResponse("edit_account_password.html", {"request": request})

@app.get("/edit-account-email", response_class=HTMLResponse)
async def edit_account_email(request: Request):
    return templates.TemplateResponse("edit_account_email.html", {"request": request})

@app.post("/update-username")
async def update_username(
    new_username: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_user_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        old_username = payload.get("sub")
        
        if not old_username:
            raise HTTPException(status_code=401, detail="Invalid token")

        if new_username == old_username:
            raise HTTPException(status_code=406, detail="New username cannot be the same as the old one")

        if db.query(User).filter(User.username == new_username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        user = db.query(User).filter(User.username == old_username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.username = new_username
        db.commit()

        log_action(db, old_username, "update-username", f"Username changed to {new_username}")

        return {"message": f"successfully updated to {new_username}"}

    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    except HTTPException as e:
        if e.status_code == 406:
            raise e
        else:
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    except Exception as e:
        print(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/update-password")
async def update_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_user_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not verify_password(old_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Old password is incorrect")

        user.hashed_password = get_password_hash(new_password)
        db.commit()
        log_action(db, username, "update-password", "Password changed successfully")
        return {"message": "Password updated successfully"}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/update-email")
async def update_email(
    new_email: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_user_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        if db.query(User).filter(User.email == new_email).first():
            raise HTTPException(status_code=400, detail="Email already in use")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.email = new_email
        db.commit()
        log_action(db, username, "update-email", f"Email changed to {new_email}")
        return {"message": "Email updated successfully"}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
@app.get("/admin-login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.get("/admin-panel", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("admin_panel.html", {"request": request})

@app.post("/admin/vaccines/add")
async def add_vaccine(
    vaccine_name: str = Form(...),
    admin_key: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db_admin: Session = Depends(get_admin_db),
    db_vaccine: Session = Depends(get_vaccine_db)
):
    # Check admin key first
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=403, detail="Admin not found")

        existing_vaccine = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == vaccine_name).first()
        if existing_vaccine:
            raise HTTPException(status_code=400, detail="Vaccine already exists")

        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        new_vaccine = Vaccine(
            vaccine_name=vaccine_name,
            date_added=current_time,
            added_by=username,
            is_active=1,
            last_modified=current_time,
            modified_by=username
        )
        
        db_vaccine.add(new_vaccine)
        db_vaccine.commit()
        
        log_action(db_admin, username, "add_vaccine", f"Added vaccine: {vaccine_name}")
        
        return {
            "message": "Vaccine added successfully",
            "vaccine_name": vaccine_name,
            "date_added": current_time,
            "added_by": username
        }

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/admin/vaccines/update")
async def update_vaccine(
    vaccine_name: str = Form(...),
    new_name: str = Form(None),
    is_active: int = Form(None),
    admin_key: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db_admin: Session = Depends(get_admin_db),
    db_vaccine: Session = Depends(get_vaccine_db)
):
    # Check admin key first
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=403, detail="Admin not found")

        vaccine = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == vaccine_name).first()
        if not vaccine:
            raise HTTPException(status_code=404, detail="Vaccine not found")

        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        changes = []
        
        if new_name and new_name != vaccine.vaccine_name:
            existing = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == new_name).first()
            if existing:
                raise HTTPException(status_code=400, detail="Vaccine name already exists")
            
            changes.append(f"name changed from {vaccine.vaccine_name} to {new_name}")
            vaccine.vaccine_name = new_name

        if is_active is not None and is_active != vaccine.is_active:
            changes.append(f"active status changed from {vaccine.is_active} to {is_active}")
            vaccine.is_active = is_active

        if changes:
            vaccine.last_modified = current_time
            vaccine.modified_by = username
            db_vaccine.commit()
            
            log_action(db_admin, username, "update_vaccine", 
                      f"Updated vaccine {vaccine_name}: " + ", ".join(changes))
            
            return {
                "message": "Vaccine updated successfully",
                "changes": changes,
                "last_modified": current_time,
                "modified_by": username
            }
        else:
            return {"message": "No changes detected"}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/admin/vaccines/delete")
async def delete_vaccine(
    vaccine_name: str = Form(...),
    admin_key: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db_admin: Session = Depends(get_admin_db),
    db_vaccine: Session = Depends(get_vaccine_db)
):
    # Check admin key first
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=403, detail="Admin not found")

        vaccine = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == vaccine_name).first()
        if not vaccine:
            raise HTTPException(status_code=404, detail="Vaccine not found")

        db_vaccine.delete(vaccine)
        db_vaccine.commit()
        
        log_action(db_admin, username, "delete_vaccine", f"Deleted vaccine: {vaccine_name}")
        
        return {"message": "Vaccine deleted successfully"}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/admin/vaccines/list")
async def list_vaccines(
    token: str = Depends(oauth2_scheme),
    db_vaccine: Session = Depends(get_vaccine_db),
    db_admin: Session = Depends(get_admin_db)
):
    """
    Returns a list of all vaccines in the database.
    Requires admin authentication.
    """
    try:
        # Verify the token and get admin username
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Verify that the user is actually an admin
        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Get all vaccines from the database
        vaccines = db_vaccine.query(Vaccine).all()
        
        # Format the response
        vaccine_list = []
        for vaccine in vaccines:
            vaccine_list.append({
                "id": vaccine.id,
                "vaccine_name": vaccine.vaccine_name,
                "date_added": vaccine.date_added,
                "added_by": vaccine.added_by,
                "is_active": bool(vaccine.is_active),
                "last_modified": vaccine.last_modified,
                "modified_by": vaccine.modified_by
            })
        
        log_action(db_admin, username, "list_vaccines", "Retrieved list of all vaccines")
        return {"vaccines": vaccine_list}
    
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
@app.get("/admin/data")
async def get_admin_data(
    token: str = Depends(oauth2_scheme),
    db_admin: Session = Depends(get_admin_db),
    db_user: Session = Depends(get_admin_db)  # Using admin_db for verification
):
    """
    Returns all data from the admin database.
    Requires admin authentication.
    """
    try:
        # Verify the token and get admin username
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Verify that the user is actually an admin
        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Get all admins from the database
        admins = db_admin.query(Admin).all()
        
        # Format the response (excluding password hashes for security)
        admin_list = []
        for admin in admins:
            admin_list.append({
                "id": admin.id,
                "username": admin.username
                # Note: We don't include the hashed_password in the response
            })
        
        log_action(db_admin, username, "get_admin_data", "Retrieved all admin data")
        return {"admins": admin_list}
    
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
@app.post("/admin/server/maintenance")
async def toggle_maintenance_mode(
    maintenance: bool = Form(...),
    admin_key: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db_admin: Session = Depends(get_admin_db)
):
    """
    Toggle server maintenance mode. When enabled, all requests will be redirected
    to a maintenance page except for the healthcheck endpoint.
    Requires admin authentication.
    """
    global SERVER_MAINTENANCE_MODE
    
    # Check admin key first
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=403, detail="Admin not found")

        SERVER_MAINTENANCE_MODE = maintenance
        
        log_action(db_admin, username, "toggle_maintenance", 
                  f"Maintenance mode set to {maintenance}")
        
        if maintenance:
            return {"message": "Maintenance mode activated. All requests will be redirected."}
        else:
            return {"message": "Maintenance mode deactivated. Server is operational."}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# Add this middleware at the end of the file, before the FastAPI app runs
@app.middleware("http")
async def maintenance_middleware(request: Request, call_next):
    global SERVER_MAINTENANCE_MODE
    
    # Allow healthcheck endpoint to work even in maintenance mode
    if request.url.path == "/healthcheck":
        return await call_next(request)
    
    if SERVER_MAINTENANCE_MODE and request.url.path != "/maintenance":
        return RedirectResponse(url="/maintenance")
    
    return await call_next(request)

# Add this endpoint to show the maintenance page
@app.get("/maintenance", response_class=HTMLResponse)
async def maintenance_page(request: Request):
    return templates.TemplateResponse("maintenance.html", {"request": request})

@app.post("/admin/security/rotate-key")
async def rotate_security_key(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db_admin: Session = Depends(get_admin_db),
    db_queue: Session = Depends(get_queue_db),
    db_user: Session = Depends(get_user_db)
):
    """
    Rotate the security key with auto-generated code and update web.config
    Requires admin authentication.
    """
    global SECRET_KEY, hashed_code, SERVER_MAINTENANCE_MODE
    
    try:
        # 1. Verify admin credentials
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload"
                )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )

        admin = db_admin.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )

        # 2. Generate new code and hash using the function
        new_code, new_hashed_code = generate_and_hash_code()
        new_secret_key = f"{hashlib.sha256(new_code.encode()).hexdigest()}"

        # 3. Enable maintenance mode
        SERVER_MAINTENANCE_MODE = True
        
        try:
            # 4. Clear the queue
            try:
                db_queue.query(Queue).delete()
                db_queue.commit()
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to clear queue: {str(e)}"
                )
            
            # 5. Re-encrypt all user passwords (using old key to verify, then hash with new key)
            users_updated = 0
            try:
                users = db_user.query(User).all()
                for user in users:
                    if user.hashed_password:
                        # Verify the password can be verified with old context
                        if pwd_context.verify(SECRET_KEY, user.hashed_password):
                            # Hash with new key
                            user.hashed_password = pwd_context.hash(new_secret_key)
                            users_updated += 1
                db_user.commit()
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to update user passwords: {str(e)}"
                )
            
            # 6. Re-encrypt all admin passwords (using old key to verify, then hash with new key)
            admins_updated = 0
            try:
                admins = db_admin.query(Admin).all()
                for admin in admins:
                    if admin.hashed_password:
                        # Verify the password can be verified with old context
                        if pwd_context.verify(SECRET_KEY, admin.hashed_password):
                            # Hash with new key
                            admin.hashed_password = pwd_context.hash(new_secret_key)
                            admins_updated += 1
                db_admin.commit()
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to update admin passwords: {str(e)}"
                )
            
            # 7. Update global security variables
            old_secret_key = SECRET_KEY
            SECRET_KEY = new_secret_key
            hashed_code = new_hashed_code
            
            # 8. Update web.config file
            try:
                config_file = "web.config"
                tree = ET.parse(config_file)
                root = tree.getroot()
                
                for elem in root.findall(".//add[@key='SECRET_KEY']"):
                    elem.set('value', new_secret_key)
                
                tree.write(config_file, encoding='utf-8', xml_declaration=True)
            except Exception as e:
                # Roll back secret key if config update fails
                SECRET_KEY = old_secret_key
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to update config file: {str(e)}"
                )
            
            # Log the action
            log_action(db_admin, username, "rotate_key", 
                     f"Security key rotated. Users updated: {users_updated}, Admins updated: {admins_updated}")
            
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "message": "Security key rotated successfully",
                    "details": {
                        "new_code_prefix": new_code[:2] + "**",
                        "users_updated": users_updated,
                        "admins_updated": admins_updated,
                        "queue_cleared": True,
                        "config_updated": True
                    }
                }
            )
            
        except Exception as e:
            # Re-raise HTTPExceptions
            if isinstance(e, HTTPException):
                raise e
            # Handle other exceptions
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unexpected error during key rotation: {str(e)}"
            )
            
        finally:
            # Always disable maintenance mode
            SERVER_MAINTENANCE_MODE = False
            
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )