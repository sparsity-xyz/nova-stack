use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::path::Path;

use crate::nitro_cli::{EIFMeasurements, NitroCLI};

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Loaded attestation - permissive parser that accepts uppercase, lowercase,
/// and nested (`{"measurements": {...}}`) shapes from various tooling.
#[derive(Debug, Clone)]
pub struct AttestationMeasurements {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub pcr8: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAttestation {
    #[serde(rename = "PCR0", alias = "pcr0")]
    pcr0: Option<String>,
    #[serde(rename = "PCR1", alias = "pcr1")]
    pcr1: Option<String>,
    #[serde(rename = "PCR2", alias = "pcr2")]
    pcr2: Option<String>,
    #[serde(rename = "PCR8", alias = "pcr8")]
    pcr8: Option<String>,
    #[serde(rename = "measurements", alias = "Measurements")]
    measurements: Option<NestedMeasurements>,
}

#[derive(Debug, Deserialize)]
struct NestedMeasurements {
    #[serde(rename = "PCR0", alias = "pcr0")]
    pcr0: Option<String>,
    #[serde(rename = "PCR1", alias = "pcr1")]
    pcr1: Option<String>,
    #[serde(rename = "PCR2", alias = "pcr2")]
    pcr2: Option<String>,
    #[serde(rename = "PCR8", alias = "pcr8")]
    pcr8: Option<String>,
}

impl AttestationMeasurements {
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read attestation file {}", path.display()))?;
        let raw: RawAttestation = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse attestation JSON {}", path.display()))?;

        let (pcr0, pcr1, pcr2, pcr8) = match raw.measurements {
            Some(nested) => (nested.pcr0, nested.pcr1, nested.pcr2, nested.pcr8),
            None => (raw.pcr0, raw.pcr1, raw.pcr2, raw.pcr8),
        };

        Ok(Self {
            pcr0: pcr0.ok_or_else(|| anyhow!("attestation missing PCR0"))?,
            pcr1: pcr1.ok_or_else(|| anyhow!("attestation missing PCR1"))?,
            pcr2: pcr2.ok_or_else(|| anyhow!("attestation missing PCR2"))?,
            pcr8,
        })
    }
}

/// Outcome of a single PCR comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrComparison {
    pub name: &'static str,
    pub expected: String,
    pub actual: String,
    pub matches: bool,
}

pub fn compare(attestation: &AttestationMeasurements, eif: &EIFMeasurements) -> Vec<PcrComparison> {
    let mut out = vec![
        compare_pcr("PCR0", &attestation.pcr0, Some(&eif.pcr0)),
        compare_pcr("PCR1", &attestation.pcr1, Some(&eif.pcr1)),
        compare_pcr("PCR2", &attestation.pcr2, Some(&eif.pcr2)),
    ];
    if let Some(att_pcr8) = &attestation.pcr8 {
        out.push(compare_pcr("PCR8", att_pcr8, eif.pcr8.as_ref()));
    }
    out
}

fn compare_pcr(name: &'static str, expected: &str, actual: Option<&String>) -> PcrComparison {
    let exp_n = normalize(expected);
    let act_n = actual.map_or_else(String::new, |value| normalize(value));
    PcrComparison {
        name,
        expected: expected.to_string(),
        actual: actual.cloned().unwrap_or_else(|| "(missing)".to_string()),
        matches: exp_n == act_n && !exp_n.is_empty(),
    }
}

fn normalize(s: &str) -> String {
    let trimmed = s.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

fn status_label(matches: bool) -> String {
    if matches {
        format!("{GREEN}CHECK{RESET}")
    } else {
        format!("{RED}X{RESET}")
    }
}

pub fn print_report(results: &[PcrComparison], quiet: bool) {
    if quiet {
        return;
    }
    println!("PCR verification report:");
    println!("  {:<6} {:<12} {:<66} actual", "PCR", "match", "expected");
    for r in results {
        println!(
            "  {:<6} {:<21} {:<66} {}",
            r.name,
            status_label(r.matches),
            r.expected,
            r.actual
        );
    }
}

pub async fn run_verify(eif: &Path, attestation: &Path, quiet: bool) -> Result<i32> {
    let attestation = AttestationMeasurements::from_file(attestation)?;
    let nitro = NitroCLI::new();
    let info = nitro
        .describe_eif(eif)
        .await
        .context("describe-eif failed (nitro-cli must be installed and EIF readable)")?;
    let results = compare(&attestation, &info.measurements);
    print_report(&results, quiet);

    let all_match = results.iter().all(|r| r.matches);
    if all_match {
        if quiet {
            println!("verified");
        } else {
            println!("verified: all PCRs match");
        }
        Ok(0)
    } else {
        for r in results.iter().filter(|r| !r.matches) {
            if quiet {
                println!("mismatch: {}", r.name);
            }
        }
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tmpfile");
        write!(f, "{}", content).unwrap();
        f
    }

    #[test]
    fn parses_uppercase_flat_attestation() {
        let f = write_temp(r#"{"PCR0":"aa","PCR1":"bb","PCR2":"cc"}"#);
        let a = AttestationMeasurements::from_file(f.path()).unwrap();
        assert_eq!(a.pcr0, "aa");
        assert_eq!(a.pcr1, "bb");
        assert_eq!(a.pcr2, "cc");
        assert!(a.pcr8.is_none());
    }

    #[test]
    fn parses_lowercase_flat_attestation() {
        let f = write_temp(r#"{"pcr0":"aa","pcr1":"bb","pcr2":"cc","pcr8":"dd"}"#);
        let a = AttestationMeasurements::from_file(f.path()).unwrap();
        assert_eq!(a.pcr0, "aa");
        assert_eq!(a.pcr8.as_deref(), Some("dd"));
    }

    #[test]
    fn parses_nested_attestation() {
        let f = write_temp(r#"{"measurements":{"PCR0":"aa","PCR1":"bb","PCR2":"cc"}}"#);
        let a = AttestationMeasurements::from_file(f.path()).unwrap();
        assert_eq!(a.pcr0, "aa");
    }

    #[test]
    fn parses_capitalized_nested_attestation() {
        let f = write_temp(r#"{"Measurements":{"PCR0":"aa","PCR1":"bb","PCR2":"cc"}}"#);
        let a = AttestationMeasurements::from_file(f.path()).unwrap();
        assert_eq!(a.pcr0, "aa");
    }

    #[test]
    fn rejects_missing_pcr0() {
        let f = write_temp(r#"{"PCR1":"bb","PCR2":"cc"}"#);
        let err = AttestationMeasurements::from_file(f.path()).unwrap_err();
        assert!(err.to_string().contains("missing PCR0"));
    }

    #[test]
    fn comparison_normalizes_case_and_prefix() {
        let att = AttestationMeasurements {
            pcr0: "0xAABBCC".to_string(),
            pcr1: "0XDDEEFF".to_string(),
            pcr2: "112233".to_string(),
            pcr8: None,
        };
        let eif = EIFMeasurements {
            pcr0: "aabbcc".to_string(),
            pcr1: "ddeeff".to_string(),
            pcr2: "112233".to_string(),
            pcr8: None,
        };
        let results = compare(&att, &eif);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.matches));
    }

    #[test]
    fn comparison_detects_mismatch() {
        let att = AttestationMeasurements {
            pcr0: "aaaa".to_string(),
            pcr1: "bbbb".to_string(),
            pcr2: "cccc".to_string(),
            pcr8: None,
        };
        let eif = EIFMeasurements {
            pcr0: "aaaa".to_string(),
            pcr1: "bbbb".to_string(),
            pcr2: "different".to_string(),
            pcr8: None,
        };
        let results = compare(&att, &eif);
        assert!(results[0].matches);
        assert!(results[1].matches);
        assert!(!results[2].matches);
    }

    #[test]
    fn comparison_includes_pcr8_when_attestation_has_it() {
        let att = AttestationMeasurements {
            pcr0: "aaaa".to_string(),
            pcr1: "bbbb".to_string(),
            pcr2: "cccc".to_string(),
            pcr8: Some("dddd".to_string()),
        };
        let eif = EIFMeasurements {
            pcr0: "aaaa".to_string(),
            pcr1: "bbbb".to_string(),
            pcr2: "cccc".to_string(),
            pcr8: None,
        };
        let results = compare(&att, &eif);
        assert_eq!(results.len(), 4);
        assert_eq!(results[3].name, "PCR8");
        assert!(!results[3].matches);
    }
}
