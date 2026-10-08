//! Catálogo de padrões.
//!
//! A jogada de performance: compilamos TODOS os padrões num `RegexSet`, que
//! faz uma passada linear única pelo arquivo e diz QUAIS padrões deram match.
//! Só para esses poucos rodamos o `Regex` individual para extrair o valor e a
//! posição. Em vez de N varreduras (regex ingênuo), é 1 + (poucos matches).
//!
//! `regex` é linear-time garantido (estilo RE2): imune a ReDoS mesmo varrendo
//! input não-confiável de alvos.

use regex::{Regex, RegexSet};

pub struct Pattern {
    pub name: &'static str,
    pub severity: &'static str, // critical | high | medium | low
    pub group: usize,           // grupo de captura com o segredo (0 = match inteiro)
    pub re: &'static str,
}

/// Formato conhecido (alta precisão) + alguns contextuais (média).
pub const PATTERNS: &[Pattern] = &[
    // ---- prefixos de provider (alta confiança) -----------------------------
    Pattern { name: "aws_access_key",     severity: "high",     group: 0, re: r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b" },
    Pattern { name: "github_token",       severity: "high",     group: 0, re: r"\bgh[oprsu]_[A-Za-z0-9]{36}\b" },
    Pattern { name: "github_pat_fg",      severity: "high",     group: 0, re: r"\bgithub_pat_[A-Za-z0-9_]{82}\b" },
    Pattern { name: "gitlab_pat",         severity: "high",     group: 0, re: r"\bglpat-[A-Za-z0-9_\-]{20}\b" },
    Pattern { name: "slack_token",        severity: "high",     group: 0, re: r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b" },
    Pattern { name: "slack_webhook",      severity: "high",     group: 0, re: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+" },
    Pattern { name: "stripe_secret",      severity: "critical", group: 0, re: r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b" },
    Pattern { name: "google_api_key",     severity: "high",     group: 0, re: r"\bAIza[0-9A-Za-z\-_]{35}\b" },
    Pattern { name: "google_oauth",       severity: "medium",   group: 0, re: r"\bya29\.[0-9A-Za-z\-_]{20,}\b" },
    Pattern { name: "sendgrid_key",       severity: "high",     group: 0, re: r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b" },
    Pattern { name: "npm_token",          severity: "high",     group: 0, re: r"\bnpm_[A-Za-z0-9]{36}\b" },
    Pattern { name: "square_token",       severity: "high",     group: 0, re: r"\bsq0(?:atp|csp)-[A-Za-z0-9\-_]{22,43}\b" },
    Pattern { name: "digitalocean_token", severity: "high",     group: 0, re: r"\bdop_v1_[a-f0-9]{64}\b" },
    Pattern { name: "openai_key",         severity: "critical", group: 0, re: r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b" },
    Pattern { name: "anthropic_key",      severity: "critical", group: 0, re: r"\bsk-ant-[A-Za-z0-9\-_]{90,}\b" },
    Pattern { name: "mailgun_key",        severity: "medium",   group: 0, re: r"\bkey-[a-z0-9]{32}\b" },
    Pattern { name: "twilio_sid",         severity: "medium",   group: 0, re: r"\bAC[a-z0-9]{32}\b" },
    Pattern { name: "jwt",                severity: "low",      group: 0, re: r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b" },
    Pattern { name: "private_key_block",  severity: "critical", group: 0, re: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----" },

    // ---- contextuais (média confiança, mais ruído) -------------------------
    Pattern { name: "generic_assignment", severity: "medium",   group: 1,
              re: r#"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)["'` ]{0,4}[:=]["'` ]{0,4}([A-Za-z0-9_\-./+]{16,80})"# },
];

/// Endpoints estilo LinkFinder: caminhos e URLs embutidos em strings do JS.
pub const ENDPOINT_RE: &str =
    r#"(?:"|')((?:https?:)?//[^"'\s]{4,}|/[A-Za-z0-9_./\-]{2,}(?:\?[^"'\s]*)?)(?:"|')"#;

pub struct Compiled {
    pub set: RegexSet,
    pub individual: Vec<Regex>,
    pub endpoint: Regex,
}

impl Compiled {
    pub fn build() -> Self {
        let set = RegexSet::new(PATTERNS.iter().map(|p| p.re)).expect("regexset");
        let individual = PATTERNS
            .iter()
            .map(|p| Regex::new(p.re).expect("regex"))
            .collect();
        let endpoint = Regex::new(ENDPOINT_RE).expect("endpoint regex");
        Self { set, individual, endpoint }
    }
}
