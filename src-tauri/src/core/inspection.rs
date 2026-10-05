//! State-free inspection of explicitly selected skill roots. This module must
//! not depend on the store, manager configuration, git, or any skill executor.
use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub code: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SkillInspection {
    pub relative_path: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub upstream: Option<String>,
    pub upstream_commit: Option<String>,
    pub payload_sha256: Option<String>,
    pub file_count: usize,
    pub payload_bytes: u64,
    /// Presence only: no evaluation is executed or scored by inspection.
    pub evals_present: bool,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct RootInspection {
    pub root: PathBuf,
    /// False when traversal or payload hashing could not inspect all content.
    pub complete: bool,
    pub skills: Vec<SkillInspection>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub relative_path: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct InspectionReport {
    pub schema_version: u32,
    pub hash_algorithm: &'static str,
    pub executable_bits_observed: bool,
    pub source: RootInspection,
    pub comparison: Option<RootInspection>,
    pub drift: Vec<Comparison>,
}

impl InspectionReport {
    pub fn complete(&self) -> bool {
        self.source.complete && self.comparison.as_ref().map_or(true, |r| r.complete)
    }

    pub fn has_findings(&self) -> bool {
        let has = |r: &RootInspection| {
            !r.findings.is_empty() || r.skills.iter().any(|s| !s.findings.is_empty())
        };
        has(&self.source)
            || self.comparison.as_ref().map_or(false, has)
            || self.drift.iter().any(|d| d.status != "identical")
    }
}

fn finding(path: impl Into<String>, code: &'static str) -> Finding {
    Finding { path: path.into(), code }
}

fn relative(path: &Path, root: &Path) -> Result<String> {
    let path = path.strip_prefix(root)?;
    let mut parts = Vec::new();
    for part in path.components() {
        parts.push(part.as_os_str().to_str().context("non-UTF-8 inspection path")?);
    }
    Ok(parts.join("/"))
}

fn ignored(name: &str) -> bool {
    matches!(name, ".git" | ".DS_Store" | "Thumbs.db" | "__pycache__")
        || name.ends_with(".pyc")
}

fn document_metadata(bytes: &[u8], skill: &mut SkillInspection) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        skill.findings.push(finding("SKILL.md", "invalid_utf8"));
        return;
    };
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        skill.findings.push(finding("SKILL.md", "missing_frontmatter"));
        return;
    }
    let mut yaml = String::new();
    let mut closed = false;
    for line in lines {
        if line == "---" {
            closed = true;
            break;
        }
        yaml.push_str(line);
        yaml.push('\n');
    }
    if !closed {
        skill.findings.push(finding("SKILL.md", "unclosed_frontmatter"));
        return;
    }
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&yaml) else {
        // Do not echo parser snippets: metadata can contain sensitive text.
        skill.findings.push(finding("SKILL.md", "invalid_frontmatter"));
        return;
    };
    skill.name = value.get("name").and_then(|v| v.as_str()).map(String::from);
    skill.description = value.get("description").and_then(|v| v.as_str()).map(String::from);
    if let Some(metadata) = value.get("metadata") {
        skill.upstream = metadata.get("upstream").and_then(|v| v.as_str()).map(String::from);
        skill.upstream_commit = metadata.get("upstream_commit").and_then(|v| v.as_str()).map(String::from);
    }
    match skill.name.as_deref() {
        Some(name) if !name.is_empty() && name.len() <= 64
            && !name.starts_with('-') && !name.ends_with('-') && !name.contains("--")
            && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') => {}
        _ => skill.findings.push(finding("SKILL.md", "invalid_name")),
    }
    match skill.description.as_deref() {
        Some(description) if !description.trim().is_empty() && description.chars().count() <= 1024 => {}
        _ => skill.findings.push(finding("SKILL.md", "invalid_description")),
    }
}

#[cfg(unix)]
fn executable(metadata: &fs::Metadata) -> u8 {
    use std::os::unix::fs::PermissionsExt;
    (metadata.permissions().mode() & 0o111 != 0) as u8
}

#[cfg(not(unix))]
fn executable(_metadata: &fs::Metadata) -> u8 { 0 }

fn open_regular_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the link itself, not its target.
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() { bail!("not a regular file"); }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { bail!("reparse point"); }
    }
    Ok(file)
}

fn inspect_skill(dir: &Path, root: &Path) -> Result<SkillInspection> {
    let mut skill = SkillInspection {
        relative_path: relative(dir, root)?, name: None, description: None,
        upstream: None, upstream_commit: None, payload_sha256: None,
        file_count: 0, payload_bytes: 0, evals_present: false, findings: Vec::new(),
    };
    let mut records = BTreeMap::new();
    let mut complete = true;
    let mut entries = 0;
    for entry in WalkDir::new(dir).follow_links(false).into_iter()
        .filter_entry(|e| e.depth() == 0 || !ignored(&e.file_name().to_string_lossy())) {
        entries += 1;
        if entries > MAX_ENTRIES {
            skill.findings.push(finding("", "entry_limit")); complete = false; break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => { skill.findings.push(finding("", "unreadable_entry")); complete = false; continue; }
        };
        let path = match relative(entry.path(), dir) {
            Ok(path) => path,
            Err(_) => {
                skill.findings.push(finding("", "unsupported_path_encoding"));
                complete = false;
                continue;
            }
        };
        if entry.file_type().is_dir() { continue; }
        if !entry.file_type().is_file() {
            skill.findings.push(finding(path, "unsupported_entry")); complete = false; continue;
        }
        // Presence is independent of read permission or the hashing budget.
        if path == "evals/evals.json" { skill.evals_present = true; }
        let result = (|| -> Result<(Vec<u8>, u64, u8)> {
            // Re-check type before opening; never intentionally follow a link.
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() { bail!("not a regular file"); }
            let limit = MAX_PAYLOAD_BYTES.saturating_sub(skill.payload_bytes);
            let limit = if path == "SKILL.md" { limit.min(MAX_DOCUMENT_BYTES) } else { limit };
            if metadata.len() > limit { bail!("payload limit"); }
            let mut file = open_regular_file(entry.path())?;
            let mut hasher = Sha256::new();
            let mut count = 0;
            let mut document = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 { break; }
                count += read as u64;
                if count > limit { bail!("payload limit"); }
                hasher.update(&buffer[..read]);
                if path == "SKILL.md" { document.extend_from_slice(&buffer[..read]); }
            }
            if path == "SKILL.md" { document_metadata(&document, &mut skill); }
            Ok((hasher.finalize().to_vec(), count, executable(&metadata)))
        })();
        match result {
            Ok((digest, bytes, exec)) => {
                skill.file_count += 1;
                skill.payload_bytes += bytes;
                records.insert(path, (digest, bytes, exec));
            }
            Err(_) => { skill.findings.push(finding(path, "unreadable_or_oversized_file")); complete = false; }
        }
    }
    if !records.contains_key("SKILL.md") {
        skill.findings.push(finding("SKILL.md", "missing_document")); complete = false;
    }
    if complete {
        let mut hasher = Sha256::new();
        hasher.update(b"skills-manager-inspection-v1\0");
        for (path, (digest, bytes, exec)) in records {
            hasher.update((path.len() as u64).to_le_bytes());
            hasher.update(path.as_bytes());
            hasher.update(bytes.to_le_bytes());
            hasher.update(digest);
            hasher.update([exec]);
        }
        skill.payload_sha256 = Some(hex::encode(hasher.finalize()));
    }
    Ok(skill)
}

fn inspect_root(root: &Path) -> Result<RootInspection> {
    let root = fs::canonicalize(root).context("inspection root unavailable")?;
    if !root.is_dir() { bail!("inspection root must be a directory"); }
    if root.to_str().is_none() { bail!("inspection root must be a UTF-8 path"); }
    let mut report = RootInspection { root, complete: true, skills: Vec::new(), findings: Vec::new() };
    let mut skill_dirs: Vec<PathBuf> = Vec::new();
    let mut entries = 0;
    let mut walker = WalkDir::new(&report.root).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        entries += 1;
        if entries > MAX_ENTRIES {
            report.findings.push(finding("", "entry_limit")); report.complete = false; break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => { report.findings.push(finding("", "unreadable_entry")); report.complete = false; continue; }
        };
        if entry.depth() > 0 && ignored(&entry.file_name().to_string_lossy()) {
            if entry.file_type().is_dir() { walker.skip_current_dir(); }
            continue;
        }
        let path = match relative(entry.path(), &report.root) {
            Ok(path) => path,
            Err(_) => {
                report.findings.push(finding("", "unsupported_path_encoding"));
                report.complete = false;
                if entry.file_type().is_dir() { walker.skip_current_dir(); }
                continue;
            }
        };
        if entry.file_type().is_symlink() {
            report.findings.push(finding(path, "unsupported_symlink"));
            report.complete = false;
        } else if entry.file_type().is_dir() {
            let marker = entry.path().join("SKILL.md");
            match fs::symlink_metadata(&marker) {
                Ok(_) => {
                    skill_dirs.push(entry.path().to_path_buf());
                    walker.skip_current_dir();
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => { report.findings.push(finding(path, "unreadable_document")); report.complete = false; }
            }
        }
    }
    skill_dirs.sort();
    for dir in skill_dirs {
        let skill = inspect_skill(&dir, &report.root)?;
        if skill.payload_sha256.is_none() { report.complete = false; }
        report.skills.push(skill);
    }
    if report.skills.is_empty() { report.findings.push(finding("", "no_skills_found")); }
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for skill in &report.skills {
        if let Some(name) = &skill.name { *names.entry(name.clone()).or_default() += 1; }
    }
    for skill in &mut report.skills {
        if skill.name.as_ref().map_or(false, |n| names[n] > 1) {
            skill.findings.push(finding("SKILL.md", "duplicate_name"));
        }
    }
    Ok(report)
}

/// Compare by relative directory, never by ambiguous frontmatter name.
pub fn inspect(root: &Path, compare: Option<&Path>) -> Result<InspectionReport> {
    let source = inspect_root(root)?;
    let comparison = compare.map(inspect_root).transpose()?;
    let mut drift = Vec::new();
    if let Some(target) = &comparison {
        let left: BTreeMap<_, _> = source.skills.iter().map(|s| (s.relative_path.clone(), s)).collect();
        let right: BTreeMap<_, _> = target.skills.iter().map(|s| (s.relative_path.clone(), s)).collect();
        let paths: BTreeSet<_> = left.keys().chain(right.keys()).cloned().collect();
        for path in paths {
            let status = match (left.get(&path), right.get(&path)) {
                (Some(a), Some(b)) => match (&a.payload_sha256, &b.payload_sha256) {
                    (Some(a), Some(b)) if a == b => "identical",
                    (Some(_), Some(_)) => "changed",
                    _ => "unverifiable",
                },
                (Some(_), None) if target.complete => "missing",
                (None, Some(_)) if source.complete => "extra",
                _ => "unverifiable",
            };
            drift.push(Comparison { relative_path: path, status });
        }
    }
    Ok(InspectionReport { schema_version: 1, hash_algorithm: "sha256-framed-payload-v1",
        executable_bits_observed: cfg!(unix), source, comparison, drift })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn skill(root: &Path, relative: &str, name: &str) -> PathBuf {
        let dir = root.join(relative);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), format!("---\nname: {name}\ndescription: Example skill\n---\n# Body\n")).unwrap();
        dir
    }

    #[test]
    fn reports_metadata_evals_and_deterministic_payload_without_writes() {
        let root = tempdir().unwrap();
        let dir = skill(root.path(), "nested/example", "example");
        fs::create_dir(dir.join("evals")).unwrap();
        fs::write(dir.join("evals/evals.json"), "{}").unwrap();
        let before = fs::read(dir.join("SKILL.md")).unwrap();
        let a = inspect(root.path(), None).unwrap();
        let b = inspect(root.path(), None).unwrap();
        assert!(a.complete());
        assert!(!a.has_findings());
        assert_eq!(a.source.skills.len(), 1);
        assert!(a.source.skills[0].evals_present);
        assert_eq!(a.source.skills[0].file_count, 2);
        assert_eq!(a.source.skills[0].payload_sha256, b.source.skills[0].payload_sha256);
        assert_eq!(before, fs::read(dir.join("SKILL.md")).unwrap());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn detects_script_drift_missing_and_extra_by_path() {
        let a = tempdir().unwrap(); let b = tempdir().unwrap();
        let left = skill(a.path(), "same", "example");
        let right = skill(b.path(), "same", "example");
        fs::write(left.join("run.sh"), "echo one").unwrap();
        fs::write(right.join("run.sh"), "echo two").unwrap();
        skill(a.path(), "missing", "missing"); skill(b.path(), "extra", "extra");
        let report = inspect(a.path(), Some(b.path())).unwrap();
        assert_eq!(report.drift.iter().map(|d| d.status).collect::<Vec<_>>(), vec!["extra", "missing", "changed"]);
    }

    #[test]
    fn duplicate_names_are_not_deduplicated_and_invalid_metadata_is_reported() {
        let root = tempdir().unwrap();
        skill(root.path(), "one", "same"); skill(root.path(), "two", "same");
        let bad = skill(root.path(), "bad", "bad");
        fs::write(bad.join("SKILL.md"), "---\nname: [\n---\n").unwrap();
        let report = inspect(root.path(), None).unwrap();
        assert_eq!(report.source.skills.len(), 3);
        assert_eq!(report.source.skills.iter().filter(|s| s.findings.iter().any(|f| f.code == "duplicate_name")).count(), 2);
        assert!(report.has_findings());
    }

    #[test]
    fn does_not_execute_scripts_or_descend_into_nested_skills() {
        let root = tempdir().unwrap(); let dir = skill(root.path(), "one", "one");
        skill(&dir, "fixture", "nested");
        fs::write(dir.join("run.sh"), "exit 99\n").unwrap();
        assert_eq!(inspect(root.path(), None).unwrap().source.skills.len(), 1);
    }

    #[test]
    fn rejects_missing_root_and_reports_oversized_document_without_hash() {
        let root = tempdir().unwrap();
        assert!(inspect(&root.path().join("absent"), None).is_err());
        let dir = skill(root.path(), "one", "one");
        let file = fs::File::create(dir.join("SKILL.md")).unwrap();
        file.set_len(MAX_DOCUMENT_BYTES + 1).unwrap();
        let report = inspect(root.path(), None).unwrap();
        assert!(!report.complete());
        assert!(report.source.skills[0].payload_sha256.is_none());
    }

    #[test]
    fn oversized_evaluation_is_present_even_when_payload_cannot_be_hashed() {
        let root = tempdir().unwrap();
        let dir = skill(root.path(), "one", "one");
        fs::create_dir(dir.join("evals")).unwrap();
        fs::File::create(dir.join("evals/evals.json")).unwrap()
            .set_len(MAX_PAYLOAD_BYTES + 1).unwrap();
        let report = inspect(root.path(), None).unwrap();
        assert!(!report.complete());
        assert!(report.source.skills[0].evals_present);
        assert!(report.source.skills[0].payload_sha256.is_none());
        assert!(report.source.skills[0].findings.iter().any(|f| f.path == "evals/evals.json"));
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_external_links_or_report_partial_hash_as_equal() {
        use std::os::unix::fs::symlink;
        let a = tempdir().unwrap(); let b = tempdir().unwrap(); let outside = tempdir().unwrap();
        let dir = skill(a.path(), "one", "one"); skill(b.path(), "one", "one");
        fs::write(outside.path().join("secret"), "must not be read").unwrap();
        symlink(outside.path().join("secret"), dir.join("linked")).unwrap();
        symlink(outside.path(), a.path().join("external")).unwrap();
        let report = inspect(a.path(), Some(b.path())).unwrap();
        assert!(!report.complete());
        assert_eq!(report.drift[0].status, "unverifiable");
        assert!(report.source.skills[0].payload_sha256.is_none());
        assert_eq!(report.source.findings[0].code, "unsupported_symlink");
    }

    #[cfg(unix)]
    #[test]
    fn relative_paths_reject_non_utf8_without_lossy_identity() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = Path::new("/");
        let path = root.join(OsString::from_vec(vec![0xff]));
        assert!(relative(&path, root).is_err());
    }

    // APFS rejects invalid-byte names before inspection can encounter them.
    // Linux filesystems permit them, so exercise the actual traversal there.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_paths_preserve_known_inventory_but_never_receive_a_hash() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = tempdir().unwrap();
        let known = skill(root.path(), "known", "known");
        fs::write(known.join(OsString::from_vec(vec![0xff])), "data").unwrap();
        let unknown = root.path().join(OsString::from_vec(vec![0xfe]));
        fs::create_dir(&unknown).unwrap();
        fs::write(unknown.join("SKILL.md"), "---\nname: unknown\ndescription: Example\n---\n").unwrap();
        let report = inspect(root.path(), None).unwrap();
        assert!(!report.complete());
        assert_eq!(report.source.skills.len(), 1);
        assert_eq!(report.source.skills[0].name.as_deref(), Some("known"));
        assert!(report.source.skills[0].payload_sha256.is_none());
        assert!(report.source.skills[0].findings.iter().any(|f| f.code == "unsupported_path_encoding"));
        assert!(report.source.findings.iter().any(|f| f.code == "unsupported_path_encoding"));
        assert!(serde_json::to_string(&report).is_ok());
    }
}
