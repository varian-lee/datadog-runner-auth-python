# datadog-runner-auth-python

**Datadog Runner** 프로젝트의 **auth-python** 마이크로서비스입니다.

## 🔗 Multi-root Workspace
이 저장소는 Multi-root Workspace의 일부입니다:
- **🏠 워크스페이스**: /Users/kihyun.lee/workspace/datadog-runner-multiroot
- **🧠 개발 환경**: Cursor Multi-root로 통합 관리
- **🔄 Git 관리**: 각 서비스 독립적 버전 관리

## 🚀 개발 환경
```bash
# Multi-root Workspace에서 개발
cd /Users/kihyun.lee/workspace/datadog-runner-multiroot
cursor datadog-runner.code-workspace

# 또는 이 서비스만 단독 개발
cursor .
```

## 📁 기술 스택
- **FastAPI**: 고성능 Python 웹 프레임워크
- **structlog**: JSON 구조화 로깅
- **PostgreSQL**: 사용자 데이터 저장
- **Redis**: 세션 캐시

## 🔐 주요 기능
- JWT 대신 세션 쿠키 인증
- SHA-256 비밀번호 해싱
- Datadog APM 자동 correlation
- 기존 demo 사용자 호환

## 🔄 배포
```bash
# 개발 이미지 빌드 및 배포
../infra/scripts/update-dev-image.sh auth-python

# 또는 통합 배포
../infra/scripts/deploy-eks-complete.sh
```

## 📊 모니터링
- **Datadog APM**: 분산 트레이싱
- **JSON 로깅**: 구조화된 로그 분석
- **Dynamic Instrumentation**: 런타임 계측
- **Exception Replay**: 예외 상태 캡처

*마지막 업데이트: 2025-09-17*
