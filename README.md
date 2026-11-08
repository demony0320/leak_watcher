# LeakWatch

두 단계로 나뉜 유출 탐지 도구. 결과는 한 저장소에서 같은 지문(fingerprint)으로 관리된다.

| 단계 | 언제 | 무엇을 | 어디서 |
| --- | --- | --- | --- |
| **CI** | PR, main merge, 야간 | 코드·설정·git 이력 | Bitbucket Pipelines (또는 아무 CI) |
| **Runtime** | 스케줄 (배포 여부 무관) | HTTPS로 닿는 실행 중 시스템 (On-prem / Cloud), DB | 단일 서버 또는 PC |

- 코어는 **Python 3.11+ 표준 라이브러리만** 사용. 폐쇄망 반입이 쉽다.
- 원문 비밀값·개인정보는 저장·전송하지 않는다. 마스킹 값 + 해시만 남는다 (리포트, 알림, Bitbucket 주석, LLM 모두).

```
 CI  ─ leakwatch ci scan ──▶ findings.json ─┐   (pipeline artifact)
                     └──▶ PR: Code Insights 리포트 + 라인 주석, JUnit
                                            ▼
 Runtime ─ leakwatch runtime daemon ─ [http · nuclei · db] + ingest(inbox) ─▶ store ─▶ alert / report
            ▲ 사람 피드백 (fp / fixed / confirm) ── 억제 규칙 + LLM 지침
            └ 운영에서 새로 찾은 패턴 → .leakwatch.toml [[ci.rules]] 로 CI에 되돌림
```

---

## CI 단계

### 검사 항목

| 항목 | 내용 |
| --- | --- |
| 비밀값 | API 키·토큰·개인키·접속 문자열 비밀번호 (내장 규칙 + 설치돼 있으면 **gitleaks**) |
| git 이력 | PR 안에서 넣었다 지운 키, (full 모드) 과거에 커밋됐다 지워진 키 |
| 개인정보 | 테스트 데이터·픽스처에 들어간 주민번호(날짜 검증)·카드번호(Luhn)·전화번호 |
| 위험 파일 | `.env`, `id_rsa`, `*.pem`, `terraform.tfstate`, 백업·덤프 |
| 코드 규칙 | id를 받는 엔드포인트에 소유자/인증 확인 없음, TLS 검증 끔, 디버그 모드, 비밀값 로그 출력, 문자열로 만든 SQL, CORS `*`+credentials, 팀 정의 규칙 |

### 모드와 차단 기준

- **diff (PR)**: PR 대상 브랜치와의 차이만 본다. `BITBUCKET_PR_DESTINATION_BRANCH`가 있으면 자동.
- **full**: 저장소 전체 (+ `--history`로 전체 git 이력).
- **차단(exit 1)** = `fail_on` 이상 **AND** 이번 PR에서 새로 생김 **AND** baseline에 없음 **AND** 해당 줄에 `leakwatch:ignore` 없음.
  기존 코드의 문제는 보고만 하고 PR을 막지 않는다.
- exit 2 = 스캐너 자체 오류 (유출과 구분).

```bash
leakwatch ci scan                              # auto: PR이면 diff, 아니면 full
leakwatch ci scan --mode diff --base origin/main
leakwatch ci scan --mode full --history
leakwatch ci baseline                          # 기존 부채 수용 → .leakwatch-baseline.json 커밋
```

### 결과물 (`--out leakwatch-results`)

- `findings.json` — 런타임 `ingest`가 읽는 파일
- `test-results/leakwatch.xml` — JUnit. Pipelines가 자동으로 테스트 결과로 표시
- `leakwatch.sarif`, `summary.md`
- **Bitbucket Code Insights**: PR에 리포트(PASSED/FAILED) + 해당 줄 주석
  - Cloud(Pipelines): 단계 안의 인증 프록시(`localhost:29418`)로 자동, 토큰 불필요
  - Data Center/Server: `BITBUCKET_SERVER_URL`, `BITBUCKET_PROJECT`, `BITBUCKET_REPO`, `BITBUCKET_TOKEN`(읽기 권한) 설정 시

### Bitbucket Pipelines에 붙이기

1. `docker build -f ci/Dockerfile.ci -t registry.corp.internal/leakwatch-ci:0.2 .` → 사내 레지스트리에 push
2. `ci/bitbucket-pipelines.yml`을 대상 저장소에 복사(또는 단계만 병합)
   - PR: diff 스캔 → PR 리포트·주석, 새 유출이면 실패
   - main: full + history 스캔 → `findings.json` 아티팩트
   - custom `leakwatch-nightly`: 저장소 설정 → Schedules에 연결
3. (선택) `ci/leakwatch.example.toml` → 저장소 루트 `.leakwatch.toml` (차단 기준, 제외 경로, 팀 규칙)

---

## Runtime 단계

### 검사 항목 (스케줄마다)

| # | 항목 | 내용 | 엔진 |
| --- | --- | --- | --- |
| 1 | 노출 경로 | `/.env`, `.git`, actuator, 디버그·테스트 페이지, 백업 파일, 디렉터리 리스팅, 버전 배너, CORS | http |
| 2 | 알려진 취약점 | CVE·설정 오류 템플릿. 템플릿을 갱신하면 다음 주기에 전체 재점검 | **nuclei** (설치 시) |
| 3 | 인가·응답 | 무인증 데이터 응답, IDOR(이웃 id 조회, 테스트 계정), 응답 속 비밀값·개인정보 | http |
| 4 | DB 저장 상태 | 평문 비밀번호, 무솔트 해시, 암호화 안 된 주민번호·카드번호 | db (읽기 전용 계정) |
| + | CI 결과 | `[ingest].watch_dir`에 넣은 `findings.json`을 같은 저장소로 | ingest |

On-prem / Cloud 구분 없이 **이 머신에서 HTTPS로 닿는 주소**를 대상으로 한다. 능동 요청은 `[scope].allowed_hosts`에 있는 호스트로만 가고, GET·SELECT만 쓴다.

```bash
cp runtime.example.toml runtime.toml          # 대상 입력
leakwatch -c runtime.toml runtime run         # 1회
leakwatch -c runtime.toml runtime daemon      # 주기 실행
leakwatch -c runtime.toml ingest leakwatch-results/findings.json
leakwatch -c runtime.toml list | show <id> | report
leakwatch -c runtime.toml feedback <id> fp --note "업무상 필요한 컬럼"   # 억제 + LLM 지침
leakwatch -c runtime.toml feedback <id> fixed  # 다음 주기에 실제로 사라졌는지 재검증
```

수명주기: 신규 → 다음 주기에 안 보이면 자동 **resolved** → 다시 보이면 **reopened**. 대상이 응답하지 않으면 그 대상의 항목은 resolved 처리하지 않는다. CI 결과는 **full 스캔**일 때만 자동 resolved (PR diff는 저장소 일부만 보므로).

---

## 데모

```bash
python demo/make_demo.py                 # demo/work/repo (main=기존 부채, feature/loan-api=새 유출 PR), app.db
# CI
cd demo/work/repo && git checkout feature/loan-api
python -m leakwatch ci scan --base main --bitbucket off      # 3 blocking (픽스처 주민번호/카드, PR 안에서 넣었다 지운 토큰)
git checkout main && python -m leakwatch ci baseline && python -m leakwatch ci scan --mode full --history   # 0 blocking
cd ../../..
# Runtime
DEMO_TOKEN=demo-user-token-1001 python demo/leaky_app.py &
mkdir -p data-demo/inbox && cp demo/work/repo/leakwatch-results/findings.json data-demo/inbox/
DEMO_TOKEN=demo-user-token-1001 python -m leakwatch -c runtime.demo.toml runtime run
# → data-demo/report.html
```

## 설치 / 폐쇄망 반입

- 코어: 소스 폴더 복사 후 `python -m leakwatch` 또는 `pip install .`
- 선택: `.[db]` (SQLAlchemy + 드라이버, SQLite 외 DB)
- 외부 도구(선택): **gitleaks** (CI 이미지에 포함), **nuclei** + 템플릿 폴더 (런타임). 없으면 해당 검사만 건너뛴다.
- 이미지: 외부에서 빌드 → `docker save` → 반입 → `docker load`

## 구성

```
leakwatch/
  common/    models · patterns(비밀값·개인정보 규칙) · config · store(수명주기) · alerts · report · triage(LLM)
  ci/        scan · git · coderules · gitleaks · outputs(JSON/JUnit/SARIF) · bitbucket(Code Insights)
  runtime/   http · nuclei · db · ingest · loop
ci/          bitbucket-pipelines.yml · Dockerfile.ci · leakwatch.example.toml
runtime.example.toml · runtime.demo.toml · Dockerfile(runtime) · docker-compose.yml(runtime demo)
demo/        leaky_app.py · make_demo.py
tests/       python -m unittest discover -s tests
```
