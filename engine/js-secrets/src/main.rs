//! Entrada do motor.
//!
//!   js-secrets --manifest manifest.jsonl [--entropy]
//!
//! manifest.jsonl: uma linha JSON por arquivo -> {"path": "...", "url": "..."}
//! Python baixa os JS/.map e escreve esse manifest; aqui varremos em paralelo
//! (rayon, sem GIL) e cuspimos um Finding JSON por linha no stdout.

mod finding;
mod patterns;
mod scan;
mod sourcemap;

use finding::Finding;
use rayon::prelude::*;
use scan::Scanner;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};

#[derive(Deserialize)]
struct Entry {
    path: String,
    url: String,
}

fn read_manifest(path: &str) -> Vec<Entry> {
    let data = fs::read_to_string(path).unwrap_or_default();
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect()
}

fn scan_entry(scanner: &Scanner, e: &Entry) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(&e.path) else {
        return Vec::new();
    };

    // .map => recupera fontes originais e varre cada uma
    if e.path.ends_with(".map") {
        let mut findings = Vec::new();
        for (name, code) in sourcemap::extract_sources(&content) {
            findings.extend(scanner.scan(&code, &e.url, true, Some(&name)));
        }
        return findings;
    }

    scanner.scan(&content, &e.url, false, None)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let manifest = args
        .windows(2)
        .find(|w| w[0] == "--manifest")
        .map(|w| w[1].clone());
    let entropy = args.iter().any(|a| a == "--entropy");

    let entries = match manifest {
        Some(m) => read_manifest(&m),
        None => {
            eprintln!("uso: js-secrets --manifest <arquivo.jsonl> [--entropy]");
            std::process::exit(2);
        }
    };

    let scanner = Scanner::new(entropy);

    // paralelismo real entre arquivos — é aqui que o Rust paga o investimento
    let mut findings: Vec<Finding> = entries
        .par_iter()
        .flat_map(|e| scan_entry(&scanner, e))
        .collect();

    // dedup global por (rule, value, source_url)
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.rule.clone(), f.value.clone(), f.source_url.clone())));

    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    let (mut n_secret, mut n_ep) = (0u32, 0u32);
    for f in &findings {
        match f.kind.as_str() {
            "endpoint" => n_ep += 1,
            _ => n_secret += 1,
        }
        let _ = writeln!(w, "{}", serde_json::to_string(f).unwrap());
    }
    let _ = w.flush();
    eprintln!(
        "[js-secrets] {} arquivos, {} secrets/entropy, {} endpoints",
        entries.len(),
        n_secret,
        n_ep
    );
}
