//! Finding + filtragem de falso-positivo.
//!
//! O trabalho de engenharia não é achar, é filtrar. Scan cru enterra você em
//! chave de exemplo, placeholder e chave pública. Aqui mora o allowlist.

use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Finding {
    pub kind: String,    // secret | endpoint | entropy
    pub rule: String,    // nome do padrão
    pub severity: String,
    pub value: String,
    pub source_url: String,
    pub from_sourcemap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sourcemap_file: Option<String>,
    pub line: usize,
}

/// Marcadores típicos de placeholder / chave de documentação.
const NOISE: &[&str] = &[
    "example", "your_", "yourapi", "placeholder", "dummy", "changeme",
    "xxxxxx", "000000", "123456", "abcdef", "test_key", "sample",
    "akiaiosfodnn7example", // exemplo oficial da AWS
    "insert", "replace", "<your", "{{", "}}", "${", "redacted", "removed",
];

pub fn is_noise(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    if NOISE.iter().any(|n| v.contains(n)) {
        return true;
    }
    // diversidade baixa: poucos caracteres distintos => provável placeholder
    let mut seen = [false; 128];
    let mut distinct = 0usize;
    for &b in value.as_bytes() {
        if (b as usize) < 128 && !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    distinct < 5
}

/// FP específico do `generic_assignment`: o lado direito do `chave = VALOR`
/// quase sempre é referência de código (`e.currentPassword`), UUID ou
/// identificador de baixa entropia — não um literal de segredo.
pub fn is_code_ref_or_id(value: &str) -> bool {
    is_dotted_identifier(value) || is_uuid(value) || shannon(value) < 3.0
}

/// Cadeia de identificadores separada por ponto: `e.currentPassword`,
/// `config.auth.password` (acesso a propriedade em JS, não segredo).
fn is_dotted_identifier(v: &str) -> bool {
    v.contains('.') && v.split('.').all(is_js_ident)
}

fn is_js_ident(seg: &str) -> bool {
    let mut chars = seg.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// UUID canônico (8-4-4-4-12 hex). Identificador, não segredo.
fn is_uuid(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Shannon entropy em bits/char — usado no fallback de entropia.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
