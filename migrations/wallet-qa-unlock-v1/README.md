# QA 무료 2별 해금 (기본 OFF)

이 파일들은 자동 마이그레이션 대상이 아니다. 실제 QA 적용은 별도 승인이 필요하다.

- 원래 `wallet_v2_secure.unlock_content(text,jsonb)`와 정식 50별 가격은 변경하지 않는다.
- 신규 `wallet_v2_qa_test` 스키마의 두 함수만 설치한다. 고정 콘텐츠는 `qa_wallet_unlock_2stars_v1`, 가격은 무료 2별이다. 무료 부족 시 유료로 대체하지 않는다.
- 기존 issuer/executor 역할과 NOLOGIN 함수 소유자를 재사용한다. 새 역할·비밀번호·테이블 직접 권한은 추가하지 않는다.
- `010_functions_disabled.sql`은 기존 QA 010/020/030 설치 후, 승인된 QA 대상 메타데이터·직접 TLS·SCRAM-PLUS·역할 검사 후 단일 설치자 트랜잭션에서만 적용한다. target GUC와 `lunari.qa_unlock_install_approved=1`이 필요하다. GUC는 실제 대상 검증을 대체하지 않는다.
- `020_execute_separate_approval.sql`은 별도 EXECUTE 승인 후만 적용한다. 위 조건 및 `lunari.qa_unlock_execute_approved=1`이 필요하다. issuer는 컨텍스트 발급 함수, executor는 2별 해금 함수만 실행한다.
- API는 `WALLET_V2_QA_UNLOCK_ENABLED=1`이 없으면 DB 작업 전 차단된다. Preview와 정확히 하나의 Firebase 허용 UID가 필요하다. DB 함수는 Firebase 자체를 검증하지 않으며, issuer 자격증명이 신뢰 경계다.
- 컨텍스트는 기존 저장소에 2분 TTL·페이로드 결합·일회 사용으로 저장한다. 전용 operation으로 정식 함수와 교차 사용을 차단한다.
- 기존 요청 PK 및 사용자/콘텐츠 PK, 지갑 행 잠금, 기존 원장 불변식으로 중복/동시 차감을 차단한다. HTTP 응답 유실 후 새 요청도 이미 해금된 콘텐츠를 추가 차감하지 않는다.
- 실패 전 COMMIT이 없으면 ROLLBACK한다. COMMIT 결과 불명확 시 자동 재시도·역복구·데이터 삭제를 하지 않고 읽기 검증으로 조사한다. issuer 컨텍스트는 별도 커밋되므로 executor 실패 시 사용하지 않은 컨텍스트가 TTL까지 남을 수 있다.
- 적용·EXECUTE·API 임시 활성화·실제 2별 차감·QA 앱 설치는 각각 이 구현 작업에 포함되지 않는다. 종료 시 API OFF 새 배포 확인 후 활성 배포를 제거한다. 거래/해금 원장은 삭제하지 않는다.
