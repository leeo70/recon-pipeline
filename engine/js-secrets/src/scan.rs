//! O scanner em si.
//!
//! Fluxo por arquivo: RegexSet (1 passada) -> extrai só os que bateram ->
//! endpoints -> entropia (opcional) -> filtro -> findings com nº de linha.

use crate::finding::{is_code_ref_or_id, is_noise, shannon, Finding};
use crate::patterns::{Compiled, PATTERNS};
use regex::Regex;

pub struct Scanner {
    c: Compiled,
    entropy: bool,
    entropy_re: Regex,
}

impl Scanner {
    pub fn new(entropy: bool) -> Self {
        Self {
            c: Compiled::build(),
            entropy,
            // tokens base64/hex longos: candidatos a segredo de formato desconhecido
            entropy_re: Regex::new(r"[A-Za-z0-9+/=_\-]{20,}").unwrap(),
        }
    }

    fn line_of(text: &str, byte_off: usize) -> usize {
        text[..byte_off.min(text.len())].bytes().filter(|&b| b == b'\n').count() + 1
    }

    pub fn scan(
        &self,
        text: &str,
        source_url: &str,
        from_sourcemap: bool,
        sourcemap_file: Option<&str>,
    ) -> Vec<Finding> {
        let mut out = Vec::new();

        // ---- secrets: prefilter via RegexSet, extrai só os que bateram ----
        for idx in self.c.set.matches(text).into_iter() {
            let p = &PATTERNS[idx];
            let re = &self.c.individual[idx];
            for caps in re.captures_iter(text) {
                let m = caps.get(p.group).or_else(|| caps.get(0));
                let Some(m) = m else { continue };
                let val = m.as_str();
                if is_noise(val) {
                    continue;
                }
                // generic_assignment: corta referência de código, UUID e id de baixa entropia
                if p.name == "generic_assignment" && is_code_ref_or_id(val) {
                    continue;
                }
                out.push(Finding {
                    kind: "secret".into(),
                    rule: p.name.into(),
                    severity: p.severity.into(),
                    value: val.chars().take(120).collect(),
                    source_url: source_url.into(),
                    from_sourcemap,
                    sourcemap_file: sourcemap_file.map(String::from),
                    line: Self::line_of(text, m.start()),
                });
            }
        }

        // ---- endpoints (estilo LinkFinder) --------------------------------
        for caps in self.c.endpoint.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                let ep = m.as_str();
                // corta lixo óbvio: extensões de asset, mime, etc.
                if ep.len() > 200 || ep.contains("//w3.org") {
                    continue;
                }
                out.push(Finding {
                    kind: "endpoint".into(),
                    rule: "linkfinder".into(),
                    severity: "info".into(),
                    value: ep.into(),
                    source_url: source_url.into(),
                    from_sourcemap,
                    sourcemap_file: sourcemap_file.map(String::from),
                    line: Self::line_of(text, m.start()),
                });
            }
        }

        // ---- entropia (fallback, ruidoso, off por padrão) -----------------
        if self.entropy {
            for m in self.entropy_re.find_iter(text) {
                let tok = m.as_str();
                if tok.len() >= 24 && shannon(tok) >= 4.0 && !is_noise(tok) {
                    out.push(Finding {
                        kind: "entropy".into(),
                        rule: "high_entropy".into(),
                        severity: "low".into(),
                        value: tok.chars().take(120).collect(),
                        source_url: source_url.into(),
                        from_sourcemap,
                        sourcemap_file: sourcemap_file.map(String::from),
                        line: Self::line_of(text, m.start()),
                    });
                }
            }
        }

        out
    }
}
