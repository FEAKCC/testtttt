from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, List


@dataclass(frozen=True)
class PatternDef:
    name: str
    category: str
    severity: str
    regex: re.Pattern[str]
    min_entropy: float = 2.5
    min_mixity: float = 0.3


RAW_PATTERNS = [
    # AWS
    ("aws_access_key_id", "cloud.aws", "high", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret_access_key", "cloud.aws", "critical", r"(?i)aws(.{0,20})?(secret|access).{0,20}?['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ("aws_arn", "cloud.aws", "medium", r"\barn:aws:[a-zA-Z0-9_-]+:[a-z0-9-]*:\d{12}:[^\s'\"]+"),
    ("aws_cognito_identity", "cloud.aws", "high", r"\b[a-z]{2}-[a-z]+-\d:[0-9a-f-]{36}\b"),
    ("aws_mws_auth", "cloud.aws", "high", r"\bamzn\.mws\.[0-9a-f-]{36}\b"),
    ("aws_session_token", "cloud.aws", "high", r"(?i)aws(.{0,20})?session(.{0,20})?token.{0,5}[=:].{0,5}['\"]?([A-Za-z0-9/+=]{32,})['\"]?"),
    # SMTP
    ("sendgrid_api", "smtp", "critical", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("mailgun_api", "smtp", "high", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("mailchimp_api", "smtp", "high", r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    ("postmark_token", "smtp", "high", r"\bpm_[A-Za-z0-9]{32,48}\b"),
    # SaaS/API
    ("github_pat", "saas", "critical", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("github_fine_grained", "saas", "critical", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("github_oauth", "saas", "high", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("github_app", "saas", "high", r"\b(ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    ("gitlab_pat", "saas", "high", r"\bglpat-[A-Za-z0-9_-]{20}\b"),
    ("slack_token", "saas", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
    ("slack_webhook", "saas", "critical", r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}"),
    ("twilio_sid", "saas", "high", r"\bAC[a-f0-9]{32}\b"),
    ("twilio_api_key", "saas", "high", r"\bSK[a-f0-9]{32}\b"),
    ("shopify_token", "saas", "high", r"\bshpat_[a-fA-F0-9]{32}\b"),
    ("cloudflare_key", "saas", "high", r"\b(?:cloudflare|cf).{0,20}(?:api|token|key).{0,20}['\"]?([A-Za-z0-9_-]{32,48})['\"]?"),
    ("openai_key", "ai", "critical", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("anthropic_key", "ai", "critical", r"\bsk-ant-[A-Za-z0-9-]{20,}\b"),
    # Payment
    ("stripe_live_secret", "payment", "critical", r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    ("stripe_restricted", "payment", "high", r"\brk_live_[A-Za-z0-9]{24,}\b"),
    ("stripe_publishable", "payment", "medium", r"\bpk_live_[A-Za-z0-9]{24,}\b"),
    ("square_token", "payment", "high", r"\bsq0atp-[A-Za-z0-9_-]{22}\b"),
    ("paypal_braintree", "payment", "high", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    # Cloud tokens
    ("digitalocean_pat", "cloud", "high", r"\bdoo_v1_[A-Za-z0-9]{64}\b"),
    ("datadog_api", "cloud", "high", r"\b[0-9a-f]{32}\b(?=.*datadog)"),
    ("vercel_token", "cloud", "high", r"\bvercel_[A-Za-z0-9]{24,}\b"),
    ("railway_token", "cloud", "high", r"\brailway_[A-Za-z0-9]{32,}\b"),
    ("supabase_key", "cloud", "high", r"\bsb_[a-zA-Z0-9]{40,}\b"),
    # DB URIs
    ("mongodb_uri", "database", "critical", r"mongodb(?:\+srv)?://[^\s'\"]+"),
    ("postgres_uri", "database", "critical", r"postgres(?:ql)?://[^\s'\"]+"),
    ("mysql_uri", "database", "critical", r"mysql://[^\s'\"]+"),
    ("redis_uri", "database", "high", r"redis://[^\s'\"]+"),
    ("mssql_uri", "database", "high", r"mssql://[^\s'\"]+"),
    ("jdbc_uri", "database", "medium", r"jdbc:(?:mysql|postgresql|sqlserver):[^\s'\"]+"),
    # Auth
    ("jwt", "auth", "high", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
    ("oauth_client_secret", "auth", "high", r"(?i)(client_secret|oauth_secret)[^\n]{0,20}[=:]\s*['\"]?[A-Za-z0-9._\-]{16,}['\"]?"),
    ("bearer_token", "auth", "high", r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ("basic_auth_header", "auth", "medium", r"\bBasic\s+[A-Za-z0-9+/]{20,}={0,2}"),
    ("firebase_key", "auth", "high", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("google_oauth", "auth", "high", r"\bya29\.[0-9A-Za-z\-_]+\b"),
    ("private_token_generic", "auth", "high", r"(?i)(token|secret|api[_-]?key)[^\n]{0,12}[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"),
    # Crypto
    ("rsa_private_key", "crypto", "critical", r"-----BEGIN RSA PRIVATE KEY-----[\s\S]{50,}-----END RSA PRIVATE KEY-----"),
    ("private_key_block", "crypto", "critical", r"-----BEGIN PRIVATE KEY-----[\s\S]{50,}-----END PRIVATE KEY-----"),
    ("ec_private_key", "crypto", "critical", r"-----BEGIN EC PRIVATE KEY-----[\s\S]{50,}-----END EC PRIVATE KEY-----"),
    ("pgp_private", "crypto", "critical", r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{50,}-----END PGP PRIVATE KEY BLOCK-----"),
    ("ssh_private", "crypto", "critical", r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{50,}-----END OPENSSH PRIVATE KEY-----"),
    # Other well-known
    ("npm_token", "package", "high", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("pypi_token", "package", "high", r"\bpypi-[A-Za-z0-9_-]{40,}\b"),
    ("docker_hub_pat", "container", "high", r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
    ("heroku_api", "paas", "high", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*heroku)"),
    ("algolia_api_key", "search", "high", r"\b[A-Za-z0-9]{32}\b(?=.*algolia)"),
    ("sendinblue_key", "smtp", "high", r"\bxkeysib-[A-Za-z0-9\-]{64,}\b"),
    ("discord_webhook", "saas", "high", r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]{68}"),
    ("telegram_bot_token", "saas", "medium", r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("atlassian_token", "saas", "high", r"\bATATT3xFfGF0[A-Za-z0-9_=]{20,}\b"),
    ("azure_storage_key", "cloud", "high", r"(?i)AccountKey=[A-Za-z0-9+/]{64}={0,2}"),
    ("azure_sas", "cloud", "high", r"\bsv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=[^&\s]+&st=[^&\s]+&spr=https?&sig=[A-Za-z0-9%]+"),
    ("gcp_service_account", "cloud", "critical", r"\"type\"\s*:\s*\"service_account\"[\s\S]{20,}\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----"),
    ("netlify_token", "cloud", "high", r"\bnfp_[A-Za-z0-9]{36}\b"),
    ("fastly_api_token", "cloud", "high", r"\bFastly\s+[A-Za-z0-9_-]{20,}\b"),
    ("auth0_client_secret", "auth", "high", r"(?i)auth0.{0,20}client_secret.{0,10}['\"]?[A-Za-z0-9_-]{32,}['\"]?"),
    ("okta_token", "auth", "high", r"\b00[a-zA-Z0-9]{18}\.[a-zA-Z0-9_-]{40,}\b"),
    ("zendesk_api_token", "saas", "medium", r"(?i)zendesk.{0,20}token.{0,8}[=:]\s*['\"]?[A-Za-z0-9]{20,}['\"]?"),
    ("segment_write_key", "analytics", "high", r"\b[A-Za-z0-9]{32}\b(?=.*segment)"),
    ("newrelic_key", "monitoring", "high", r"\bNRAK-[A-Za-z0-9]{27}\b"),
    ("splunk_hec", "monitoring", "high", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*splunk)"),
]


PATTERNS: List[PatternDef] = [
    PatternDef(name=n, category=c, severity=s, regex=re.compile(p, re.MULTILINE))
    for n, c, s, p in RAW_PATTERNS
]

KEYWORDS = sorted(
    {token.lower() for p in PATTERNS for token in re.split(r"[_\W]+", p.name) if len(token) > 2}
)

EXTENSION_CATEGORY_FILTER: Dict[str, set[str]] = {
    ".env": {"auth", "database", "cloud.aws", "cloud", "payment", "smtp", "saas"},
    ".js": {"auth", "saas", "payment", "ai", "cloud", "smtp"},
    ".map": {"auth", "database", "cloud", "crypto", "saas", "payment", "ai", "smtp"},
    ".json": {"auth", "database", "cloud", "crypto", "saas", "ai"},
    ".yaml": {"auth", "database", "cloud", "crypto"},
    ".yml": {"auth", "database", "cloud", "crypto"},
    ".php": {"database", "auth", "smtp", "saas", "payment"},
    ".sql": {"database", "auth"},
    ".py": {"auth", "database", "cloud", "crypto", "ai"},
    ".rb": {"auth", "database", "cloud", "saas"},
    ".go": {"auth", "cloud", "database", "crypto"},
    ".conf": {"auth", "database", "smtp", "cloud"},
}
