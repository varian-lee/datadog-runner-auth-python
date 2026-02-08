"""
🔐 Auth Service (Python FastAPI) - Datadog Runner 프로젝트

인증 및 사용자 관리 마이크로서비스
- 하이브리드 인증: 기존 demo 사용자(평문) + 신규 사용자(SHA-256 해싱)
- 세션 기반 인증: Redis 세션 스토어 (24시간 TTL)
- 점수 제출: 게임 점수를 Redis ZSET에 저장
- Datadog APM: ddtrace-run으로 자동 계측
- CORS: 분산 트레이싱 헤더 지원 (RUM-APM 연결)

엔드포인트:
- POST /api/auth/login     : 로그인 (쿠키 기반 세션)
- POST /api/auth/signup    : 회원가입 (자동 로그인)
- GET  /api/auth/logout    : 로그아웃 (세션 삭제)
- GET  /api/session/me     : 현재 사용자 정보
- POST /api/score          : 게임 점수 제출
"""
import os, secrets, time, hashlib
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from pydantic import BaseModel
import asyncpg
import redis.asyncio as aioredis
#from ddtrace import patch_all; patch_all()  # Datadog APM 트레이싱
import logging
from starlette.middleware.cors import CORSMiddleware
from ddtrace import tracer
import structlog

# Datadog 공식 방식: structlog로 trace correlation 설정
def tracer_injection(logger, log_method, event_dict):
    """Datadog trace correlation을 위한 processor"""
    # 현재 tracer context에서 correlation ID 가져오기
    event_dict.update(tracer.get_log_correlation_context())
    return event_dict

def add_message_field(logger, log_method, event_dict):
    """event 필드를 message 필드로 이동"""
    if 'event' in event_dict:
        event_dict['message'] = event_dict['event']
        # event 필드 삭제
        del event_dict['event']
    return event_dict

# structlog 설정 - JSON 출력 + Datadog correlation
structlog.configure(
    processors=[
        tracer_injection,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        add_message_field,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# 표준 logging도 structlog로 연결
logging.basicConfig(
    format="%(message)s",
    stream=None,
    level=logging.INFO,
)

# structlog logger 생성
logger = structlog.get_logger()

app = FastAPI(title="auth-python")
# CORS 설정 - 프론트엔드에서 쿠키 기반 인증 및 RUM-APM 연결 허용
app.add_middleware(CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=[
        "*",
        "x-datadog-trace-id",
        "x-datadog-parent-id", 
        "x-datadog-origin",
        "x-datadog-sampling-priority",
        "traceparent",
        "tracestate",
        "b3"
    ],
    expose_headers=[
        "x-datadog-trace-id",
        "x-datadog-parent-id",
        "traceparent",
        "tracestate"
    ]
)

# 데이터베이스 및 세션 설정
PG_DSN   = os.getenv("PG_DSN", "postgresql://app:app@postgres:5432/app")
REDIS_DSN= os.getenv("REDIS_DSN", "redis://redis:6379/0")
COOKIE_NAME = "sid"
SESSION_TTL = 60*60*24  # 24시간 세션 유지

async def get_pg():
    return await asyncpg.connect(PG_DSN)

async def get_redis():
    return await aioredis.from_url(REDIS_DSN, decode_responses=True)

# 헬스체크 엔드포인트 - ALB 헬스체크용
@app.get("/")
async def health_check():
    return {"status": "healthy", "service": "auth-python"}

# 요청 데이터 모델
class LoginIn(BaseModel):
    id: str
    pw: str

# 회원가입 기능 추가를 위한 새로운 모델 - 기존 demo 전용에서 확장
class SignupIn(BaseModel):
    id: str    # 최소 3글자 (프론트엔드 및 서버에서 검증)
    pw: str    # 최소 4글자 (프론트엔드 및 서버에서 검증)
    profile: dict = None  # 회원가입 시 프로필 정보 (선택)

def hash_password(password: str) -> str:
    """
    SHA-256 기반 비밀번호 해싱 - 회원가입 시 보안 강화
    기존 demo 사용자(평문 저장)와 호환성 유지하면서 새 사용자는 해시 적용
    데모 목적으로 간단한 SHA-256 사용 (프로덕션에서는 bcrypt, scrypt 등 권장)
    """
    return hashlib.sha256(password.encode()).hexdigest()

# 로그인 엔드포인트 - 기존 demo 사용자와 새 사용자 모두 지원
@app.post("/auth/login")
@app.post("/api/auth/login")
async def login(inp: LoginIn, resp: Response):
    pg = await get_pg()
    row = await pg.fetchrow("SELECT id, pw_hash FROM users WHERE id=$1", inp.id)
    await pg.close()
    if not row:
        raise HTTPException(401, "no user")
    
    # 비밀번호 검증 - 기존 demo 사용자와 해시된 비밀번호 모두 지원
    # init.sql의 기존 demo 사용자: pw_hash = "demo" (평문)
    # 새로 가입한 사용자: pw_hash = SHA-256 해시값
    if row["pw_hash"] == "demo" and inp.pw == "demo":
        # 레거시 demo 사용자 처리 (하위 호환성)
        pass
    elif hash_password(inp.pw) != row["pw_hash"]:
        raise HTTPException(401, "bad pw")
    
    # 세션 생성 및 쿠키 설정
    sid = secrets.token_urlsafe(24)
    r = await get_redis()
    await r.setex(f"session:{sid}", SESSION_TTL, row["id"])
    await r.close()
    resp.set_cookie(COOKIE_NAME, sid, httponly=True, secure=False, samesite="lax", max_age=SESSION_TTL)
    return {"ok": True}

# 회원가입 엔드포인트 - 기존 demo 전용 시스템을 일반 사용자로 확장
# 입력 검증, 중복 체크, 비밀번호 해싱, 자동 로그인까지 처리
@app.post("/auth/signup")
@app.post("/api/auth/signup")
async def signup(inp: SignupIn, resp: Response):
    # 입력 검증 - 프론트엔드에서도 체크하지만 서버에서 재검증 (보안)
    if not inp.id or len(inp.id) < 3:
        raise HTTPException(400, "ID는 3글자 이상이어야 합니다")
    if not inp.pw or len(inp.pw) < 4:
        raise HTTPException(400, "비밀번호는 4글자 이상이어야 합니다")
    
    pg = await get_pg()
    
    # 중복 ID 체크 - 기존 demo 사용자 포함 모든 사용자와 중복 방지
    existing_user = await pg.fetchrow("SELECT id FROM users WHERE id=$1", inp.id)
    if existing_user:
        await pg.close()
        raise HTTPException(400, "이미 존재하는 아이디입니다")
    
    # 새 사용자 생성 - SHA-256으로 해싱된 비밀번호와 함께 저장
    import json
    hashed_pw = hash_password(inp.pw)
    profile_json = json.dumps(inp.profile) if inp.profile else '{}'
    await pg.execute(
        "INSERT INTO users(id, pw_hash, profile) VALUES ($1, $2, $3::jsonb)", 
        inp.id, hashed_pw, profile_json
    )
    await pg.close()
    
    # 회원가입 후 자동 로그인 - UX 개선을 위해 바로 세션 생성하고 쿠키 설정
    sid = secrets.token_urlsafe(24)
    r = await get_redis()
    await r.setex(f"session:{sid}", SESSION_TTL, inp.id)
    await r.close()
    resp.set_cookie(COOKIE_NAME, sid, httponly=True, secure=False, samesite="lax", max_age=SESSION_TTL)
    
    return {"ok": True, "message": "회원가입이 완료되었습니다"}

@app.get("/session/me")
@app.get("/api/session/me")
async def me(req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(401)
    r = await get_redis()
    uid = await r.get(f"session:{sid}")
    await r.close()
    if not uid:
        raise HTTPException(401)
    return {"user_id": uid}

@app.get("/auth/logout")
@app.get("/api/auth/logout")
async def logout(resp: Response, req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if sid:
        r = await get_redis()
        await r.delete(f"session:{sid}")
        await r.close()
    resp.delete_cookie(COOKIE_NAME)
    return {"ok": True}

class ScoreIn(BaseModel):
    score: int

class CustomizationIn(BaseModel):
    bodyColor: str = "white"
    hatCode: str = "none"

class ProfileIn(BaseModel):
    gender: str = ""
    ageGroup: str = ""
    region: str = ""
    gameLove: str = ""
    datadogExp: str = ""

# 🎨 커스터마이징 저장 (업적 조건 검증)
@app.post("/customization")
@app.post("/api/customization")
async def save_customization(inp: CustomizationIn, req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(401)
    
    r = await get_redis()
    uid = await r.get(f"session:{sid}")
    await r.close()
    if not uid:
        raise HTTPException(401)
    
    pg = await get_pg()
    try:
        import json
        
        # 🏆 업적 조건 검증 - 최고 점수 & 플레이 횟수 조회
        stats_row = await pg.fetchrow("""
            SELECT 
                COALESCE(MAX(high_score), 0) as best_score,
                COUNT(*) as play_count
            FROM scores 
            WHERE user_id = $1
        """, uid)
        
        best_score = int(stats_row["best_score"]) if stats_row else 0
        play_count = int(stats_row["play_count"]) if stats_row else 0
        
        # 📋 프로필 완성도 조회 (별빛/갓 옵션 검증용)
        profile_row = await pg.fetchrow("SELECT profile FROM users WHERE id = $1", uid)
        profile = {}
        if profile_row and profile_row["profile"]:
            profile = json.loads(profile_row["profile"]) if isinstance(profile_row["profile"], str) else profile_row["profile"]
        
        profile_fields = ['gender', 'ageGroup', 'region', 'gameLove', 'datadogExp']
        filled_count = sum(1 for field in profile_fields if profile.get(field))
        profile_completion = int((filled_count / len(profile_fields)) * 100)
        
        # 🔒 몸 색상 검증: 기본(white) 외 선택 시 플레이 10회 이상 필요
        if inp.bodyColor != "white" and play_count < 10:
            logger.warning("커스터마이징 저장 거부 - 플레이 횟수 부족", 
                          user_id=uid, bodyColor=inp.bodyColor, play_count=play_count)
            raise HTTPException(403, f"몸 색상 변경은 플레이 10회 이상 필요합니다. (현재: {play_count}회)")
        
        # 🔒 모자 검증: 기본(none) 외 선택 시 최고 점수 500점 이상 필요
        if inp.hatCode != "none" and best_score < 500:
            logger.warning("커스터마이징 저장 거부 - 최고 점수 부족", 
                          user_id=uid, hatCode=inp.hatCode, best_score=best_score)
            raise HTTPException(403, f"모자 변경은 최고 점수 500점 이상 필요합니다. (현재: {best_score}점)")
        
        # 🔒 특별 옵션 검증: 별빛(starlight)/갓(gat) 선택 시 프로필 완성도 100% 필요
        if inp.bodyColor == "starlight" and profile_completion < 100:
            logger.warning("커스터마이징 저장 거부 - 히든 조건 미충족 (별빛)", 
                          user_id=uid, profile_completion=profile_completion)
            raise HTTPException(403, f"이 색상은 히든 조건 충족이 필요합니다. (현재: {profile_completion}%)")
        
        if inp.hatCode == "gat" and profile_completion < 100:
            logger.warning("커스터마이징 저장 거부 - 히든 조건 미충족 (갓)", 
                          user_id=uid, profile_completion=profile_completion)
            raise HTTPException(403, f"이 모자는 히든 조건 충족이 필요합니다. (현재: {profile_completion}%)")
        
        # users 테이블에 customization 컬럼 업데이트
        await pg.execute(
            """
            UPDATE users 
            SET customization = $2::jsonb 
            WHERE id = $1
            """, 
            uid, 
            f'{{"bodyColor": "{inp.bodyColor}", "hatCode": "{inp.hatCode}"}}'
        )
        logger.info("커스터마이징 저장 완료", user_id=uid, bodyColor=inp.bodyColor, hatCode=inp.hatCode)
    except HTTPException:
        raise  # 403 에러는 그대로 전달
    except Exception as e:
        logger.error("커스터마이징 저장 실패", error=str(e))
        raise HTTPException(500, "저장에 실패했습니다")
    finally:
        await pg.close()
    
    return {"ok": True}

# 🎨 커스터마이징 조회 (업적 정보 포함)
@app.get("/customization")
@app.get("/api/customization")
async def get_customization(req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(401)
    
    r = await get_redis()
    uid = await r.get(f"session:{sid}")
    await r.close()
    if not uid:
        raise HTTPException(401)
    
    pg = await get_pg()
    try:
        import json
        
        # 커스터마이징 + 프로필 데이터 조회
        row = await pg.fetchrow("SELECT customization, profile FROM users WHERE id = $1", uid)
        customization = {"bodyColor": "white", "hatCode": "none"}
        profile = {}
        if row:
            if row["customization"]:
                customization = json.loads(row["customization"]) if isinstance(row["customization"], str) else row["customization"]
            if row["profile"]:
                profile = json.loads(row["profile"]) if isinstance(row["profile"], str) else row["profile"]
        
        # 📋 프로필 완성도 계산 (5개 필드: gender, ageGroup, region, gameLove, datadogExp)
        profile_fields = ['gender', 'ageGroup', 'region', 'gameLove', 'datadogExp']
        filled_count = sum(1 for field in profile_fields if profile.get(field))
        profile_completion = int((filled_count / len(profile_fields)) * 100)
        
        # 🏆 업적 정보 조회 - 최고 점수, 플레이 횟수, 누적 점수
        stats_row = await pg.fetchrow("""
            SELECT 
                COALESCE(MAX(high_score), 0) as best_score,
                COUNT(*) as play_count,
                COALESCE(SUM(high_score), 0) as total_score
            FROM scores 
            WHERE user_id = $1
        """, uid)
        
        best_score = int(stats_row["best_score"]) if stats_row else 0
        play_count = int(stats_row["play_count"]) if stats_row else 0
        total_score = int(stats_row["total_score"]) if stats_row else 0
        
        return {
            **customization,
            "achievements": {
                "bestScore": best_score,
                "playCount": play_count,
                "totalScore": total_score,
                "profileCompletion": profile_completion,
                "canSelectHat": best_score >= 500,           # 최고점수 500 이상
                "canSelectColor": play_count >= 10,          # 플레이 10회 이상
                "canSelectSpecial": profile_completion >= 100  # 프로필 완성도 100% (별빛/갓)
            }
        }
    except Exception as e:
        logger.error("커스터마이징 조회 실패", error=str(e))
        return {
            "bodyColor": "white", 
            "hatCode": "none",
            "achievements": {
                "bestScore": 0,
                "playCount": 0,
                "totalScore": 0,
                "profileCompletion": 0,
                "canSelectHat": False,
                "canSelectColor": False,
                "canSelectSpecial": False
            }
        }
    finally:
        await pg.close()

# 📋 프로필 조회
@app.get("/profile")
@app.get("/api/profile")
async def get_profile(req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(401)
    
    r = await get_redis()
    uid = await r.get(f"session:{sid}")
    await r.close()
    if not uid:
        raise HTTPException(401)
    
    pg = await get_pg()
    try:
        import json
        row = await pg.fetchrow("SELECT profile FROM users WHERE id = $1", uid)
        profile = {}
        if row and row["profile"]:
            profile = json.loads(row["profile"]) if isinstance(row["profile"], str) else row["profile"]
        return profile
    except Exception as e:
        logger.error("프로필 조회 실패", error=str(e))
        return {}
    finally:
        await pg.close()

# 📋 프로필 저장
@app.post("/profile")
@app.post("/api/profile")
async def save_profile(inp: ProfileIn, req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(401)
    
    r = await get_redis()
    uid = await r.get(f"session:{sid}")
    await r.close()
    if not uid:
        raise HTTPException(401)
    
    pg = await get_pg()
    try:
        import json
        profile_data = {
            "gender": inp.gender,
            "ageGroup": inp.ageGroup,
            "region": inp.region,
            "gameLove": inp.gameLove,
            "datadogExp": inp.datadogExp
        }
        await pg.execute(
            "UPDATE users SET profile = $2::jsonb WHERE id = $1",
            uid, json.dumps(profile_data)
        )
        logger.info("프로필 저장 완료", user_id=uid, profile=profile_data)
        return {"ok": True}
    except Exception as e:
        logger.error("프로필 저장 실패", error=str(e))
        raise HTTPException(500, "프로필 저장에 실패했습니다")
    finally:
        await pg.close()

@app.post("/score")
@app.post("/api/score")
async def submit_score(inp: ScoreIn, req: Request):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(401)
    
    # 세션 확인 (Redis)
    r = await get_redis()
    uid = await r.get(f"session:{sid}")
    await r.close()
    if not uid:
        raise HTTPException(401)
    
    # 점수 저장 (PostgreSQL)
    pg = await get_pg()
    try:
        # 모든 점수를 기록 - ranking-java에서 MAX() 집계로 처리
        await pg.execute(
            "INSERT INTO scores (user_id, high_score) VALUES ($1, $2)", 
            uid, inp.score
        )
        logger.info("점수 저장 완료!!!", user_id=uid, score=inp.score)
    except Exception as e:
        logger.error("점수 저장 실패!!!", error=str(e))
        raise HTTPException(500, "점수 저장에 실패했습니다")
    finally:
        await pg.close()
    
    return {"ok": True}
