//! The JSON verdict: every check with its outcome, plus `h_k` per MPC entry for cross-checking.

use std::fmt::Write;

use serde::Serialize;

/// One check and its outcome.
#[derive(Debug, Serialize)]
pub struct Check {
    /// Stable identifier: callers require the exact set of ids they expect.
    pub id: String,
    /// What the check verifies, for people.
    pub title: String,
    /// Whether it passed.
    pub ok: bool,
    /// The problems found, `; `-separated; absent when it passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One MPC entry of the final key, as this implementation reads it.
#[derive(Debug, Serialize)]
pub struct EntryReport {
    /// 1-based position in the chain.
    pub index: usize,
    /// `contribution` or `beacon`.
    pub kind: &'static str,
    /// The contributor name, when the entry has one (not covered by `h_k`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `h_k`: BLAKE2b-512 of the entry's public key and transcript, hex.
    pub hash: String,
}

/// The verifier's answer: printed as JSON by the binary.
#[derive(Debug, Default, Serialize)]
pub struct Verdict {
    /// True only if there is at least one check and every check passed.
    pub ok: bool,
    /// Name and version of this implementation.
    pub verifier: &'static str,
    /// csHash of the final key, hex; absent when the keys did not parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cs_hash: Option<String>,
    /// The final key's MPC entries.
    pub entries: Vec<EntryReport>,
    /// Every check, in a fixed order.
    pub checks: Vec<Check>,
}

impl Verdict {
    /// An empty verdict carrying this implementation's name and version.
    pub fn new() -> Self {
        Self {
            verifier: concat!("ceremony-verifier ", env!("CARGO_PKG_VERSION")),
            ..Self::default()
        }
    }

    /// Records a check; `problems` empty means it passed.
    pub fn check(&mut self, (id, title): (&str, &str), problems: &[String]) {
        let ok = problems.is_empty();
        let detail = (!ok).then(|| problems.join("; "));
        self.checks.push(Check {
            id: id.into(),
            title: title.into(),
            ok,
            detail,
        });
    }

    /// Sets `ok` from the checks recorded so far.
    #[must_use]
    pub fn finish(mut self) -> Self {
        self.ok = !self.checks.is_empty() && self.checks.iter().all(|c| c.ok);
        self
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
