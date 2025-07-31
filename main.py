from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import zipfile, io, json

app = FastAPI()

# ✅ CORS 설정 (React 등 프론트에서 호출 가능하게)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://insta-dive.com",
        "https://www.insta-dive.com",
        "http://localhost:5173",  # 개발 환경
        "http://localhost:4173"   # 빌드 미리보기
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ✅ Origin 검증 미들웨어 (일시적으로 완화)
@app.middleware("http")
async def validate_origin_middleware(request: Request, call_next):
    try:
        origin = request.headers.get("origin")
        user_agent = request.headers.get("user-agent", "")
        
        # 디버깅을 위한 로깅
        print(f"Request: {request.method} {request.url.path}")
        print(f"Origin: {origin}")
        print(f"User-Agent: {user_agent[:100]}...")
        
        # 일시적으로 모든 origin 허용 (디버깅용)
        print(f"Allowing request from origin: {origin}")
        
        response = await call_next(request)
        return response
    except Exception as e:
        print(f"Error in origin middleware: {e}")
        # 예외가 발생해도 서버가 종료되지 않도록 처리
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )

# ✅ 헬스체크 엔드포인트
@app.get("/")
async def health_check():
    return {"status": "healthy", "message": "InstaDive API is running"}

# ✅ 보안 설정
MAX_SIZE = 50 * 1024 * 1024  # 압축 해제 용량 제한 (50MB)
MAX_FILES = 100              # zip 내 파일 개수 제한
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".py", ".sh"]  # 위험 확장자

# ✅ zip 폭탄 방지 - 용량 검사
def is_zip_safe(zip_bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        return sum(info.file_size for info in z.infolist()) <= MAX_SIZE

# ✅ 파일 수 검사
def has_too_many_files(zip_bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        return len(z.infolist()) > MAX_FILES

# ✅ 위험한 확장자 포함 여부
def has_dangerous_files(zip_bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        return any(name.lower().endswith(tuple(DANGEROUS_EXTENSIONS)) for name in z.namelist())

# ✅ followers_1.json / following.json 분석
def extract_usernames_from_zip(zip_bytes: bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_file:
        namelist = zip_file.namelist()
        followers_path = next((n for n in namelist if 'followers_1.json' in n), None)
        following_path = next((n for n in namelist if 'following.json' in n), None)

        if not followers_path or not following_path:
            raise HTTPException(status_code=400, detail="followers_1.json 또는 following.json이 누락됨")

        # followers
        with zip_file.open(followers_path) as f:
            followers_data = json.load(f)
            followers = {
                entry["value"]
                for item in followers_data
                for entry in item.get("string_list_data", [])
            }

        # following
        with zip_file.open(following_path) as f:
            following_data = json.load(f)
            following = {
                entry["value"]
                for item in following_data.get("relationships_following", [])
                for entry in item.get("string_list_data", [])
            }

        return followers, following

# ✅ 최근 언팔한 계정
def extract_recently_unfollowed(zip_bytes: bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_file:
        try:
            with zip_file.open("connections/followers_and_following/recently_unfollowed_profiles.json") as f:
                data = json.load(f)
                return [
                    entry["string_list_data"][0]["value"]
                    for entry in data.get("relationships_unfollowed_users", [])
                    if entry.get("string_list_data")
                ]
        except KeyError:
            return []

# ✅ 차단한 계정 목록 추출
def extract_blocked_users(zip_bytes: bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_file:
        try:
            with zip_file.open("connections/followers_and_following/blocked_profiles.json") as f:
                data = json.load(f)
                return [
                    entry["title"]
                    for entry in data.get("relationships_blocked_users", [])
                ]
        except KeyError:
            return []

# ✅ 팔로우 요청(pending) 목록 추출
def extract_pending_requests(zip_bytes: bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_file:
        try:
            with zip_file.open("connections/followers_and_following/pending_follow_requests.json") as f:
                data = json.load(f)
                return [
                    entry["string_list_data"][0]["value"]
                    for entry in data.get("relationships_follow_requests_sent", [])
                    if entry.get("string_list_data")
                ]
        except KeyError:
            return []

# ✅ 분석 API
@app.post("/analyze")
async def analyze_zip_files(
    new_zip: UploadFile = File(...),
    old_zip: UploadFile = File(None),
):
    # 🔍 new_zip 검사
    new_bytes = await new_zip.read()
    if not is_zip_safe(new_bytes):
        raise HTTPException(status_code=400, detail="new_zip 압축 해제 용량 초과")
    if has_too_many_files(new_bytes):
        raise HTTPException(status_code=400, detail="new_zip 파일 수 초과")
    if has_dangerous_files(new_bytes):
        raise HTTPException(status_code=400, detail="new_zip에 위험한 파일이 포함됨")

    # ✅ 주요 정보 추출
    new_followers, new_following = extract_usernames_from_zip(new_bytes)
    recently_unfollowed = extract_recently_unfollowed(new_bytes)
    blocked_users = extract_blocked_users(new_bytes)
    pending_requests = extract_pending_requests(new_bytes)

    # 🔍 old_zip 비교
    if old_zip:
        old_bytes = await old_zip.read()
        if not is_zip_safe(old_bytes):
            raise HTTPException(status_code=400, detail="old_zip 압축 해제 용량 초과")
        if has_too_many_files(old_bytes):
            raise HTTPException(status_code=400, detail="old_zip 파일 수 초과")
        if has_dangerous_files(old_bytes):
            raise HTTPException(status_code=400, detail="old_zip에 위험한 파일이 포함됨")
        old_followers, _ = extract_usernames_from_zip(old_bytes)
        unfollowers = sorted(list(old_followers - new_followers))
    else:
        unfollowers = []

    # ✅ 맞팔하지 않는 계정 계산
    not_following_back = sorted(list(new_following - new_followers))

    # ✅ 반환 결과
    return {
        "unfollowers": unfollowers,
        "not_following_back": not_following_back,
        "recently_unfollowed": recently_unfollowed,
        "blocked_users": blocked_users,
        "pending_requests": pending_requests
    }
