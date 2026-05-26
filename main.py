import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import secrets
import time as pytime
from base64 import b64decode, b64encode
from datetime import date, datetime, time, timedelta, timezone
from urllib.parse import parse_qsl, quote_plus, urlencode, urlparse, urlunparse
from typing import Optional, Set

import paho.mqtt.client as mqtt
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine, desc, text
from sqlalchemy.orm import declarative_base, sessionmaker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gps-tracker")

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-now")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

def build_database_url() -> str:
    explicit_url = os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url

    db_host = os.getenv("DB_HOST", "").strip()
    if not db_host:
        return "sqlite:///./gps.db"

    db_port = os.getenv("DB_PORT", "5432").strip()
    db_name = os.getenv("DB_NAME", "postgres").strip()
    db_user = os.getenv("DB_USER", "postgres").strip()
    db_password = os.getenv("DB_PASSWORD", "").strip()
    db_sslmode = os.getenv("DB_SSLMODE", "require").strip()

    password_part = f":{quote_plus(db_password)}" if db_password else ""
    return f"postgresql+psycopg://{db_user}{password_part}@{db_host}:{db_port}/{db_name}?sslmode={db_sslmode}"


def add_ipv4_hostaddr(database_url: str) -> str:
    parsed = urlparse(database_url)
    hostname = parsed.hostname
    if not hostname:
        return database_url

    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if "hostaddr" in query_params:
        return database_url

    try:
        ipv4_info = socket.getaddrinfo(hostname, parsed.port or 5432, socket.AF_INET, socket.SOCK_STREAM)
        if not ipv4_info:
            return database_url
        ipv4 = ipv4_info[0][4][0]
    except socket.gaierror:
        return database_url

    query_params["hostaddr"] = ipv4
    new_query = urlencode(query_params)
    return urlunparse(parsed._replace(query=new_query))


DATABASE_URL = build_database_url()
DB_FORCE_IPV4 = os.getenv("DB_FORCE_IPV4", "true").lower() in {"1", "true", "yes"}
if DB_FORCE_IPV4 and DATABASE_URL.startswith("postgresql"):
    DATABASE_URL = add_ipv4_hostaddr(DATABASE_URL)
if DATABASE_URL.startswith("sqlite"):
    logger.warning("DATABASE_URL no configurada para PostgreSQL; usando SQLite local (no recomendado para producción)")

MQTT_HOST = os.getenv("MQTT_HOST", "")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "vehicles/+/gps")
MQTT_COMMAND_TOPIC = os.getenv("MQTT_COMMAND_TOPIC", "vehicles/{device_id}/cmd")
MQTT_TLS = os.getenv("MQTT_TLS", "true").lower() in {"1", "true", "yes"}
MQTT_TLS_INSECURE = os.getenv("MQTT_TLS_INSECURE", "false").lower() in {"1", "true", "yes"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)


class VehiclePosition(Base):
    __tablename__ = "vehicle_positions"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(120), index=True, nullable=False)
    lat = Column(Float, nullable=False)
    lng = Column(Float, nullable=False)
    speed = Column(Float, nullable=True)
    heading = Column(Float, nullable=True)
    altitude = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class VehicleClient(Base):
    __tablename__ = "vehicle_clients"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(120), unique=True, index=True, nullable=False)
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_topic = Column(String(255), nullable=True)


app = FastAPI(title="GPS Tracker MQTT", version="2.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 600_000


def get_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, dklen=32)
    return f"{PASSWORD_SCHEME}${PASSWORD_ITERATIONS}${b64encode(salt).decode()}${b64encode(digest).decode()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        scheme, rounds_str, salt_b64, digest_b64 = password_hash.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        rounds = int(rounds_str)
        salt = b64decode(salt_b64)
        expected = b64decode(digest_b64)
    except (ValueError, TypeError):
        return False

    digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, rounds, dklen=len(expected))
    return hmac.compare_digest(digest, expected)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def ensure_admin_user():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == ADMIN_USER).first()
        if not user:
            user = User(username=ADMIN_USER, password_hash=get_password_hash(ADMIN_PASSWORD))
            db.add(user)
            db.commit()
            logger.info("Admin user created: %s", ADMIN_USER)
    finally:
        db.close()


def authenticate_user(username: str, password: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            return None
        return user
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme)):
    unauthorized = HTTPException(status_code=401, detail="No autorizado", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise unauthorized
    except JWTError as exc:
        raise unauthorized from exc

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise unauthorized
        return user
    finally:
        db.close()


class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active.discard(websocket)

    async def broadcast(self, message: dict):
        dead = []
        payload = json.dumps(message, default=str)
        for ws in list(self.active):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()
mqtt_client_instance: Optional[mqtt.Client] = None


def init_database_schema(retries: int = 5, delay_seconds: float = 2.0) -> bool:
    for attempt in range(1, retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            return True
        except Exception as exc:
            logger.error(
                "No se pudo inicializar la base de datos (intento %s/%s): %s",
                attempt,
                retries,
                exc,
            )
            if attempt < retries:
                pytime.sleep(delay_seconds)
    return False


def parse_vehicle_payload(topic: str, payload: bytes) -> dict:
    raw = payload.decode("utf-8", errors="ignore")
    data = json.loads(raw)

    parts = topic.split("/")
    device_id = data.get("device_id") or (parts[1] if len(parts) >= 3 else "unknown")

    lat = float(data["lat"])
    lng = float(data["lng"])
    speed = float(data.get("speed")) if data.get("speed") not in (None, "") else None
    heading = float(data.get("heading")) if data.get("heading") not in (None, "") else None
    altitude = float(data.get("altitude")) if data.get("altitude") not in (None, "") else None
    accuracy = float(data.get("accuracy")) if data.get("accuracy") not in (None, "") else None

    return {
        "device_id": str(device_id),
        "topic": topic,
        "lat": lat,
        "lng": lng,
        "speed": speed,
        "heading": heading,
        "altitude": altitude,
        "accuracy": accuracy,
        "raw": raw,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def save_position(data: dict):
    db = SessionLocal()
    try:
        register_or_update_vehicle_client(db, data["device_id"], data.get("topic"))
        ensure_vehicle_day_table(data["device_id"])
        db.add(
            VehiclePosition(
                device_id=data["device_id"],
                lat=data["lat"],
                lng=data["lng"],
                speed=data.get("speed"),
                heading=data.get("heading"),
                altitude=data.get("altitude"),
                accuracy=data.get("accuracy"),
                raw=data.get("raw"),
            )
        )
        db.commit()
        save_position_in_vehicle_day_table(db, data)
        db.commit()
    finally:
        db.close()


def register_or_update_vehicle_client(db, device_id: str, topic: Optional[str] = None):
    now = datetime.now(timezone.utc)
    client = db.query(VehicleClient).filter(VehicleClient.device_id == device_id).first()
    if client is None:
        db.add(VehicleClient(device_id=device_id, first_seen_at=now, last_seen_at=now, last_topic=topic))
    else:
        client.last_seen_at = now
        if topic:
            client.last_topic = topic


def sanitize_table_fragment(value: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in value.strip())
    safe = safe.strip("_")
    return safe or "unknown"


def get_vehicle_day_table_name(device_id: str, day: date) -> str:
    device = sanitize_table_fragment(device_id)
    return f"vehicle_{device}_{day.strftime('%Y%m%d')}"


def ensure_vehicle_day_table(device_id: str, day: Optional[date] = None):
    table_day = day or datetime.now(timezone.utc).date()
    table_name = get_vehicle_day_table_name(device_id, table_day)
    if engine.dialect.name == "sqlite":
        id_column = "INTEGER PRIMARY KEY AUTOINCREMENT"
        created_at_column = "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
    else:
        id_column = "BIGSERIAL PRIMARY KEY"
        created_at_column = "TIMESTAMPTZ NOT NULL DEFAULT NOW()"

    sql = f"""
    CREATE TABLE IF NOT EXISTS "{table_name}" (
        id {id_column},
        device_id VARCHAR(120) NOT NULL,
        lat DOUBLE PRECISION NOT NULL,
        lng DOUBLE PRECISION NOT NULL,
        speed DOUBLE PRECISION NULL,
        heading DOUBLE PRECISION NULL,
        altitude DOUBLE PRECISION NULL,
        accuracy DOUBLE PRECISION NULL,
        raw TEXT NULL,
        created_at {created_at_column}
    )
    """
    with engine.begin() as conn:
        conn.execute(text(sql))


def save_position_in_vehicle_day_table(db, data: dict):
    day = datetime.now(timezone.utc).date()
    table_name = get_vehicle_day_table_name(data["device_id"], day)
    sql = text(
        f"""
        INSERT INTO "{table_name}"
        (device_id, lat, lng, speed, heading, altitude, accuracy, raw, created_at)
        VALUES (:device_id, :lat, :lng, :speed, :heading, :altitude, :accuracy, :raw, :created_at)
        """
    )
    db.execute(
        sql,
        {
            "device_id": data["device_id"],
            "lat": data["lat"],
            "lng": data["lng"],
            "speed": data.get("speed"),
            "heading": data.get("heading"),
            "altitude": data.get("altitude"),
            "accuracy": data.get("accuracy"),
            "raw": data.get("raw"),
            "created_at": datetime.now(timezone.utc),
        },
    )


def on_mqtt_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        logger.info("MQTT conectado")
        client.subscribe(MQTT_TOPIC, qos=1)
        logger.info("Suscrito a %s", MQTT_TOPIC)
    else:
        logger.error("MQTT conexión fallida rc=%s", rc)


def on_mqtt_message(client, userdata, msg):
    try:
        data = parse_vehicle_payload(msg.topic, msg.payload)
        save_position(data)
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "gps", **data}), userdata["loop"])
    except Exception as e:
        logger.exception("Error procesando MQTT: %s", e)


def start_mqtt(loop: asyncio.AbstractEventLoop):
    if not MQTT_HOST:
        logger.warning("MQTT_HOST no configurado, el servicio iniciará sin escuchar MQTT")
        return

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.user_data_set({"loop": loop})
    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message

    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

    if MQTT_TLS:
        context = ssl.create_default_context()
        client.tls_set_context(context)
        if MQTT_TLS_INSECURE:
            client.tls_insecure_set(True)

    logger.info("Conectando MQTT a %s:%s", MQTT_HOST, MQTT_PORT)
    try:
        client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        client.loop_start()
    except Exception as exc:
        logger.exception("No se pudo iniciar MQTT: %s", exc)

    return client


class VehicleCommand(BaseModel):
    device_id: str
    action: str


def publish_vehicle_command(device_id: str, action: str):
    if mqtt_client_instance is None:
        raise HTTPException(status_code=503, detail="Cliente MQTT no disponible")

    action_key = action.strip().lower()
    if action_key not in {"on", "off"}:
        raise HTTPException(status_code=400, detail="Acción inválida. Use 'on' o 'off'")

    topic = MQTT_COMMAND_TOPIC.format(device_id=device_id)
    payload = json.dumps(
        {
            "device_id": device_id,
            "action": "engine_on" if action_key == "on" else "engine_off",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    result = mqtt_client_instance.publish(topic, payload=payload, qos=1)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise HTTPException(status_code=502, detail="No se pudo publicar comando MQTT")
    return {"ok": True, "topic": topic, "payload": json.loads(payload)}


@contextlib.asynccontextmanager
async def lifespan(app_instance: FastAPI):
    del app_instance
    global mqtt_client_instance
    db_ready = init_database_schema(
        retries=int(os.getenv("DB_INIT_RETRIES", "8")),
        delay_seconds=float(os.getenv("DB_INIT_RETRY_SECONDS", "2")),
    )
    if db_ready:
        ensure_admin_user()
    else:
        logger.error("La app inicia sin DB disponible; endpoints con DB pueden fallar hasta que se recupere conexión.")
    mqtt_client_instance = start_mqtt(asyncio.get_running_loop())
    try:
        yield
    finally:
        if mqtt_client_instance is not None:
            mqtt_client_instance.loop_stop()
            mqtt_client_instance.disconnect()
            mqtt_client_instance = None


app.router.lifespan_context = lifespan


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/app", response_class=HTMLResponse)
def app_page(request: Request):
    return templates.TemplateResponse("app.html", {"request": request})


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    token = create_access_token({"sub": user.username})
    return JSONResponse({"access_token": token, "token_type": "bearer"})


@app.get("/api/latest")
def latest(current_user=Depends(get_current_user)):
    del current_user
    db = SessionLocal()
    try:
        row = db.query(VehiclePosition).order_by(desc(VehiclePosition.created_at)).first()
        if not row:
            return {"ok": True, "data": None}
        return {
            "ok": True,
            "data": {
                "device_id": row.device_id,
                "lat": row.lat,
                "lng": row.lng,
                "speed": row.speed,
                "heading": row.heading,
                "altitude": row.altitude,
                "accuracy": row.accuracy,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            },
        }
    finally:
        db.close()


@app.get("/api/devices")
def devices(current_user=Depends(get_current_user)):
    del current_user
    db = SessionLocal()
    try:
        rows = db.query(VehicleClient.device_id).order_by(VehicleClient.device_id.asc()).all()
        return {"devices": sorted([r[0] for r in rows])}
    finally:
        db.close()


@app.get("/api/history/{device_id}")
def history(device_id: str, limit: int = 500, current_user=Depends(get_current_user)):
    del current_user
    db = SessionLocal()
    try:
        rows = (
            db.query(VehiclePosition)
            .filter(VehiclePosition.device_id == device_id)
            .order_by(desc(VehiclePosition.created_at))
            .limit(min(limit, 3000))
            .all()
        )
        rows.reverse()
        return {"device_id": device_id, "points": [_row_to_point(r) for r in rows]}
    finally:
        db.close()


@app.get("/api/history/{device_id}/day")
def history_by_day(
    device_id: str,
    day: date = Query(..., description="Formato YYYY-MM-DD en UTC"),
    current_user=Depends(get_current_user),
):
    del current_user
    start = datetime.combine(day, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    db = SessionLocal()
    try:
        rows = (
            db.query(VehiclePosition)
            .filter(VehiclePosition.device_id == device_id)
            .filter(VehiclePosition.created_at >= start)
            .filter(VehiclePosition.created_at < end)
            .order_by(VehiclePosition.created_at.asc())
            .all()
        )
        return {"device_id": device_id, "day": day.isoformat(), "points": [_row_to_point(r) for r in rows]}
    finally:
        db.close()


@app.post("/api/vehicle/command")
def vehicle_command(command: VehicleCommand, current_user=Depends(get_current_user)):
    del current_user
    return publish_vehicle_command(command.device_id, command.action)


def _row_to_point(row: VehiclePosition) -> dict:
    return {
        "lat": row.lat,
        "lng": row.lng,
        "speed": row.speed,
        "heading": row.heading,
        "altitude": row.altitude,
        "accuracy": row.accuracy,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub"):
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "10000"))
    uvicorn.run("main:app", host=host, port=port)
