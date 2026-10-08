//! Source maps.
//!
//! `.map` é ouro: o campo `sourcesContent` carrega o código ORIGINAL (TS
//! inclusive) antes de minificar. Segredo que estava picado no bundle volta
//! legível. Aqui a gente lê o JSON e devolve cada fonte original pra varrer.

use serde::Deserialize;

#[derive(Deserialize)]
struct SourceMap {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
}

/// Devolve pares (nome_da_fonte, conteúdo_original).
pub fn extract_sources(raw: &str) -> Vec<(String, String)> {
    let Ok(sm) = serde_json::from_str::<SourceMap>(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, content) in sm.sources_content.into_iter().enumerate() {
        if let Some(code) = content {
            let name = sm.sources.get(i).cloned().unwrap_or_else(|| format!("source_{i}"));
            out.push((name, code));
        }
    }
    out
}
