from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import string
import random
import hashlib
from datetime import datetime

app = FastAPI(
    title="CloudShort AI & Geo-Shield API",
    description="Chmurowy mikroserwis URL z dwoma modułami innowacyjnymi: AI Anti-DDoS oraz Geo-Fencing.",
    version="5.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# MODELE DANYCH (DTO / Entity)
# ==========================================
class AuthDTO(BaseModel):
    username: str
    password: str

class LinkCreateDTO(BaseModel):
    target_url: str
    blocked_countries: Optional[str] = ""

class ClickLogEntity(BaseModel):
    log_id: int
    link_id: int
    clicked_at: str
    country: str
    user_agent: Optional[str]
    ip_hash: Optional[str]
    ai_risk_score: int
    is_anomaly: int
    block_reason: Optional[str]

class LinkEntity(BaseModel):
    id: int
    owner_username: str
    short_code: str
    target_url: str
    blocked_countries: str
    clicks: int
    created_at: str
    status: str
    ai_risk_score: int
    threat_reason: Optional[str]


# ==========================================
# SZABLONY STRON BLOKADY (HTML UI)
# ==========================================
def render_block_page(title: str, badge: str, code_status: str, subtitle: str, details: str, accent_color: str, icon: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} | CloudShort Shield</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body {{
                background-color: #060913;
                background-image: radial-gradient(circle at 50% 0%, {accent_color}33 0%, transparent 60%),
                                  linear-gradient(to right, #1e293b22 1px, transparent 1px),
                                  linear-gradient(to bottom, #1e293b22 1px, transparent 1px);
                background-size: 100% 100%, 32px 32px, 32px 32px;
            }}
        </style>
    </head>
    <body class="text-white min-h-screen flex items-center justify-center p-6 font-sans">
        <div class="max-w-lg w-full bg-slate-900/80 backdrop-blur-xl border border-slate-700/80 rounded-3xl p-8 shadow-2xl text-center relative overflow-hidden">
            <div class="absolute top-0 left-0 w-full h-1.5" style="background: {accent_color};"></div>
            
            <div class="w-20 h-20 mx-auto mb-6 rounded-2xl flex items-center justify-center text-4xl shadow-lg border border-white/10" style="background: {accent_color}22;">
                {icon}
            </div>

            <span class="inline-block px-3.5 py-1 rounded-full text-xs font-bold tracking-wider uppercase mb-4 border" 
                  style="color: {accent_color}; border-color: {accent_color}55; background: {accent_color}15;">
                {badge} • {code_status}
            </span>

            <h1 class="text-2xl md:text-3xl font-extrabold tracking-tight text-white mb-3">{title}</h1>
            <p class="text-slate-400 text-sm leading-relaxed mb-6">{subtitle}</p>

            <div class="bg-slate-950/90 border border-slate-800 rounded-2xl p-4 text-left font-mono text-xs space-y-2 mb-6">
                <div class="flex justify-between text-slate-500">
                    <span>SYSTEM OCHRONY:</span>
                    <span class="text-slate-300 font-semibold">CloudShort Edge Security v5.0</span>
                </div>
                <div class="flex justify-between text-slate-500">
                    <span>SZCZEGÓŁY ZDARZENIA:</span>
                    <span style="color: {accent_color};" class="font-semibold text-right max-w-[240px]">{details}</span>
                </div>
                <div class="flex justify-between text-slate-500">
                    <span>CZAS ZDARZENIA (UTC):</span>
                    <span class="text-slate-300">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}</span>
                </div>
            </div>

            <a href="/" class="inline-flex items-center justify-center w-full py-3 px-6 rounded-xl font-semibold text-sm bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                ← Powrót do panelu CloudShort
            </a>
        </div>
    </body>
    </html>
    """


# ==========================================
# INNOWACJA 1: AISecurityEngine (AI Anti-DDoS)
# ==========================================
class AISecurityEngine:
    def __init__(self, flood_window_sec: int = 10, max_clicks_in_window: int = 5):
        self.flood_window_sec = flood_window_sec
        self.max_clicks_in_window = max_clicks_in_window
        self.suspicious_agents = ["bot", "crawler", "spider", "curl", "python", "scrapy", "ddos", "flood"]

    def evaluate_request(self, recent_logs: List[dict], user_agent: str, ip_hash: str) -> dict:
        risk_score = 5
        reasons = []
        now = datetime.utcnow()

        recent_count = 0
        same_ip_burst = 0
        for log in recent_logs:
            try:
                log_time = datetime.strptime(log["clicked_at"], "%Y-%m-%d %H:%M:%S")
                if (now - log_time).total_seconds() <= self.flood_window_sec:
                    recent_count += 1
                    if log["ip_hash"] == ip_hash:
                        same_ip_burst += 1
            except Exception:
                pass

        if recent_count >= self.max_clicks_in_window:
            risk_score += 65
            reasons.append(f"Anomalia DDoS ({recent_count + 1} żądań w {self.flood_window_sec}s)")
        elif recent_count >= 3:
            risk_score += 35
            reasons.append("Podwyższona częstotliwość kliknięć")

        if same_ip_burst >= 4:
            risk_score += 30
            reasons.append("Seryjne żądania z jednego IP")

        if any(bot in user_agent.lower() for bot in self.suspicious_agents):
            risk_score += 45
            reasons.append("Sygnatura bota/skryptu")

        risk_score = min(100, risk_score)
        is_blocked = risk_score >= 75

        return {
            "risk_score": risk_score,
            "is_blocked": is_blocked,
            "reason": " | ".join(reasons) if reasons else "Ruch bezpieczny"
        }


# ==========================================
# INNOWACJA 2: GeoSecurityEngine (Geo-Fencing)
# ==========================================
class GeoSecurityEngine:
    COUNTRY_NAMES = {
        "PL": "Polska 🇵🇱",
        "IN": "Indie 🇮🇳",
        "US": "USA 🇺🇸",
        "DE": "Niemcy 🇩🇪",
        "CN": "Chiny 🇨🇳",
        "BR": "Brazylia 🇧🇷",
        "UNKNOWN": "Nieznany region"
    }

    def detect_country(self, request: Request, forced_country: Optional[str] = None) -> str:
        if forced_country:
            return forced_country.strip().upper()
        cf_country = request.headers.get("cf-ipcountry") or request.headers.get("x-country-code")
        if cf_country:
            return cf_country.strip().upper()
        return "PL"

    def is_country_blocked(self, country_code: str, blocked_countries_csv: str) -> bool:
        if not blocked_countries_csv:
            return False
        blocked_list = [c.strip().upper() for c in blocked_countries_csv.split(",") if c.strip()]
        return country_code.upper() in blocked_list


# ==========================================
# WARSTWA DANYCH: LinkRepository
# ==========================================
class LinkRepository:
    def __init__(self, db_name: str = "links.db"):
        self.db_name = db_name
        self.init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_username TEXT NOT NULL,
                    short_code TEXT UNIQUE NOT NULL,
                    target_url TEXT NOT NULL,
                    blocked_countries TEXT DEFAULT '',
                    clicks INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    status TEXT DEFAULT 'ACTIVE',
                    ai_risk_score INTEGER DEFAULT 0,
                    threat_reason TEXT DEFAULT 'Ruch bezpieczny'
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS click_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    link_id INTEGER NOT NULL,
                    clicked_at TEXT NOT NULL,
                    country TEXT DEFAULT 'PL',
                    user_agent TEXT,
                    ip_hash TEXT,
                    ai_risk_score INTEGER DEFAULT 0,
                    is_anomaly INTEGER DEFAULT 0,
                    block_reason TEXT DEFAULT 'OK',
                    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
                );
            """)

    def create_user(self, username: str, password_hash: str) -> bool:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, password_hash, now)
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username: str, password_hash: str) -> bool:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND password_hash = ?",
                (username, password_hash)
            ).fetchone()
            return row is not None

    def save(self, owner: str, short_code: str, target_url: str, blocked_countries: str, created_at: str) -> dict:
        clean_geo = ",".join([c.strip().upper() for c in blocked_countries.split(",") if c.strip()])
        with self._get_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO links (owner_username, short_code, target_url, blocked_countries, created_at) VALUES (?, ?, ?, ?, ?)",
                (owner, short_code, target_url, clean_geo, created_at)
            )
            return {
                "id": cursor.lastrowid,
                "owner_username": owner,
                "short_code": short_code,
                "target_url": target_url,
                "blocked_countries": clean_geo,
                "clicks": 0,
                "created_at": created_at,
                "status": "ACTIVE",
                "ai_risk_score": 0,
                "threat_reason": "Ruch bezpieczny"
            }

    def find_by_code(self, code: str) -> Optional[dict]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM links WHERE short_code = ?", (code,)).fetchone()
            return dict(row) if row else None

    def find_all_by_user(self, owner: str) -> List[dict]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM links WHERE owner_username = ? ORDER BY id DESC",
                (owner,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_recent_logs(self, link_id: int, limit: int = 15) -> List[dict]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM click_logs WHERE link_id = ? ORDER BY log_id DESC LIMIT ?",
                (link_id, limit)
            ).fetchall()
            return [dict(r) for r in rows]

    def record_event(self, link_id: int, country: str, user_agent: str, ip_hash: str,
                     risk_score: int, is_blocked: bool, block_type: str, reason: str) -> None:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            if not is_blocked:
                conn.execute(
                    "UPDATE links SET clicks = clicks + 1, ai_risk_score = ?, status = 'ACTIVE', threat_reason = ? WHERE id = ?",
                    (risk_score, reason, link_id)
                )
            elif block_type == "AI_DDOS":
                conn.execute(
                    "UPDATE links SET ai_risk_score = ?, status = 'BLOCKED_BY_AI', threat_reason = ? WHERE id = ?",
                    (risk_score, reason, link_id)
                )
            conn.execute(
                """INSERT INTO click_logs (link_id, clicked_at, country, user_agent, ip_hash, ai_risk_score, is_anomaly, block_reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (link_id, now, country, user_agent, ip_hash, risk_score, 1 if is_blocked else 0, reason)
            )

    def unlock_link(self, code: str, owner: str) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE links SET status = 'ACTIVE', ai_risk_score = 0, threat_reason = 'Odblokowano przez właściciela' WHERE short_code = ? AND owner_username = ?",
                (code, owner)
            )
            return cursor.rowcount > 0

    def get_logs_for_link(self, code: str, owner: str) -> List[dict]:
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT c.* FROM click_logs c
                JOIN links l ON l.id = c.link_id
                WHERE l.short_code = ? AND l.owner_username = ?
                ORDER BY c.log_id DESC LIMIT 30
            """, (code, owner)).fetchall()
            return [dict(r) for r in rows]

    def delete_by_code(self, code: str, owner: str) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM links WHERE short_code = ? AND owner_username = ?", (code, owner))
            return cursor.rowcount > 0


# ==========================================
# WARSTWA LOGIKI BIZNESOWEJ: LinkService
# ==========================================
class LinkService:
    def __init__(self, repo: LinkRepository, ai_engine: AISecurityEngine, geo_engine: GeoSecurityEngine):
        self.repo = repo
        self.ai_engine = ai_engine
        self.geo_engine = geo_engine
        self.code_length = 6

    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def generate_code(self) -> str:
        chars = string.ascii_letters + string.digits
        while True:
            code = ''.join(random.choice(chars) for _ in range(self.code_length))
            if not self.repo.find_by_code(code):
                return code

    def shorten_url(self, owner: str, target_url: str, blocked_countries: str) -> dict:
        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        short_code = self.generate_code()
        created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        return self.repo.save(owner, short_code, url, blocked_countries, created_at)

    def process_redirect(self, code: str, user_agent: str, client_ip: str, country: str) -> dict:
        link = self.repo.find_by_code(code)
        if not link:
            return {"status": "not_found"}

        ip_hash = hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:16]

        if self.geo_engine.is_country_blocked(country, link["blocked_countries"]):
            country_name = self.geo_engine.COUNTRY_NAMES.get(country, country)
            reason = f"Kraj {country} ({country_name}) znajduje się na czarnej liście Geo-Block"
            self.repo.record_event(
                link_id=link["id"], country=country, user_agent=user_agent, ip_hash=ip_hash,
                risk_score=100, is_blocked=True, block_type="GEO_BLOCK", reason=reason
            )
            return {"status": "geo_blocked", "country": country_name, "reason": reason}

        if link["status"] == "BLOCKED_BY_AI":
            self.repo.record_event(
                link_id=link["id"], country=country, user_agent=user_agent, ip_hash=ip_hash,
                risk_score=100, is_blocked=True, block_type="AI_DDOS", reason=link["threat_reason"]
            )
            return {"status": "ai_blocked", "reason": link["threat_reason"], "risk_score": 100}

        recent_logs = self.repo.get_recent_logs(link["id"])
        ai_verdict = self.ai_engine.evaluate_request(recent_logs, user_agent, ip_hash)

        self.repo.record_event(
            link_id=link["id"], country=country, user_agent=user_agent, ip_hash=ip_hash,
            risk_score=ai_verdict["risk_score"], is_blocked=ai_verdict["is_blocked"],
            block_type="AI_DDOS" if ai_verdict["is_blocked"] else "NONE",
            reason=ai_verdict["reason"]
        )

        if ai_verdict["is_blocked"]:
            return {"status": "ai_blocked", "reason": ai_verdict["reason"], "risk_score": ai_verdict["risk_score"]}

        return {"status": "ok", "target_url": link["target_url"]}


ai_engine = AISecurityEngine()
geo_engine = GeoSecurityEngine()
repository = LinkRepository()
service = LinkService(repository, ai_engine, geo_engine)


# ==========================================
# ENDPOINTY API
# ==========================================
@app.get("/", include_in_schema=False)
def serve_dashboard():
    return FileResponse("index.html")

@app.post("/api/auth/register")
def register_user(dto: AuthDTO):
    username = dto.username.strip().lower()
    if len(username) < 3 or len(dto.password) < 3:
        raise HTTPException(status_code=400, detail="Login i hasło muszą mieć min. 3 znaki")
    if not repository.create_user(username, service.hash_password(dto.password)):
        raise HTTPException(status_code=409, detail="Użytkownik już istnieje")
    return {"status": "registered", "username": username}

@app.post("/api/auth/login")
def login_user(dto: AuthDTO):
    username = dto.username.strip().lower()
    if not repository.verify_user(username, service.hash_password(dto.password)):
        raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")
    return {"status": "logged_in", "username": username}

@app.post("/api/links", response_model=LinkEntity)
def create_link(dto: LinkCreateDTO, x_user: str = Header(default="guest")):
    if not dto.target_url.strip():
        raise HTTPException(status_code=400, detail="Adres URL nie może być pusty")
    return service.shorten_url(x_user, dto.target_url, dto.blocked_countries or "")

@app.get("/api/links", response_model=List[LinkEntity])
def get_my_links(x_user: str = Header(default="guest")):
    return repository.find_all_by_user(x_user)

@app.get("/api/links/{code}/logs", response_model=List[ClickLogEntity])
def get_link_logs(code: str, x_user: str = Header(default="guest")):
    return repository.get_logs_for_link(code, x_user)

@app.post("/api/links/{code}/simulate-ddos")
def simulate_ddos_attack(code: str, x_user: str = Header(default="guest")):
    link = repository.find_by_code(code)
    if not link or link["owner_username"] != x_user:
        raise HTTPException(status_code=404, detail="Nie znaleziono linku")
    for i in range(6):
        service.process_redirect(code, user_agent="BotNet-DDoS/2.1 (python-requests)", client_ip=f"192.168.1.{10+i}", country="US")
    return {"status": "attack_simulated"}

@app.post("/api/links/{code}/unlock")
def unlock_link(code: str, x_user: str = Header(default="guest")):
    repository.unlock_link(code, x_user)
    return {"status": "unlocked"}

@app.get("/s/{code}")
def redirect_url(code: str, request: Request, sim_country: Optional[str] = None):
    user_agent = request.headers.get("user-agent", "Unknown Browser")
    client_ip = request.client.host if request.client else "127.0.0.1"
    country = geo_engine.detect_country(request, sim_country)

    result = service.process_redirect(code, user_agent, client_ip, country)

    if result["status"] == "not_found":
        html = render_block_page(
            title="Nie znaleziono linku",
            badge="BŁĄD 404",
            code_status="NOT FOUND",
            subtitle="Podany skrócony adres URL nie istnieje lub został usunięty przez właściciela.",
            details=f"Kod skrótu: /{code}",
            accent_color="#94a3b8",
            icon="🔍"
        )
        return HTMLResponse(content=html, status_code=404)

    if result["status"] == "geo_blocked":
        html = render_block_page(
            title="Dostęp zablokowany regionalnie",
            badge="GEO-FENCING SHIELD",
            code_status="HTTP 403 FORBIDDEN",
            subtitle="Właściciel tego linku ograniczył dostęp dla użytkowników łączących się z Twojego kraju.",
            details=result["reason"],
            accent_color="#0ea5e9",
            icon="🌍"
        )
        return HTMLResponse(content=html, status_code=403)

    if result["status"] == "ai_blocked":
        html = render_block_page(
            title="Link zablokowany przez AI Shield",
            badge="AI ANTI-DDOS PROTECTION",
            code_status="HTTP 429 TOO MANY REQUESTS",
            subtitle="System sztucznej inteligencji wykrył podejrzany skok ruchu lub atak botów i tymczasowo wstrzymał przekierowania.",
            details=f"AI Risk Score: {result['risk_score']}% • {result['reason']}",
            accent_color="#f43f5e",
            icon="🛡️"
        )
        return HTMLResponse(content=html, status_code=429)

    return RedirectResponse(url=result["target_url"], status_code=307)

@app.delete("/api/links/{code}")
def delete_link(code: str, x_user: str = Header(default="guest")):
    repository.delete_by_code(code, x_user)
    return {"status": "deleted"}