use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};

use crate::{
    hash,
    manifest::{self, FileEntry, Manifest, ManifestError},
};

const MAX_TREE_ENTRIES: usize = 200_000;

#[derive(Debug)]
pub enum TreeError {
    Io(io::Error),
    Manifest(ManifestError),
    UnsupportedObject(String),
    OutputInsideRoot,
    ResourceLimit(&'static str),
    IntegrityMismatch(VerificationReport),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Manifest(error) => write!(f, "invalid manifest: {error}"),
            Self::UnsupportedObject(path) => write!(f, "unsupported filesystem object at {path}"),
            Self::OutputInsideRoot => {
                f.write_str("manifest and signature outputs must be outside the scanned root")
            }
            Self::ResourceLimit(limit) => write!(f, "directory scan exceeds the {limit} limit"),
            Self::IntegrityMismatch(report) => write!(
                f,
                "directory contents do not match the manifest ({} missing, {} modified, {} unexpected)",
                report.missing_files, report.modified_files, report.unexpected_files
            ),
        }
    }
}

impl std::error::Error for TreeError {}

impl From<io::Error> for TreeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ManifestError> for TreeError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerificationReport {
    pub matched_files: u64,
    pub missing_files: u64,
    pub modified_files: u64,
    pub unexpected_files: u64,
}

struct VerificationState<'a> {
    expected: HashMap<&'a str, &'a FileEntry>,
    found: HashSet<String>,
    report: VerificationReport,
    total_bytes: u64,
    actual_count: usize,
    total_entries: usize,
}

impl VerificationReport {
    pub fn is_verified(&self) -> bool {
        self.missing_files == 0 && self.modified_files == 0 && self.unexpected_files == 0
    }
}

pub fn create_manifest(root: &Path, output: &Path) -> Result<Manifest, TreeError> {
    if output_is_inside_root(root, output)? {
        return Err(TreeError::OutputInsideRoot);
    }
    let root_dir = open_root(root)?;
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    let mut encoded_budget = 46usize;
    let mut total_entries = 0usize;
    visit_directory(
        &root_dir,
        "",
        &mut files,
        &mut total_bytes,
        &mut encoded_budget,
        &mut total_entries,
    )?;
    let manifest = Manifest::new(files)?;
    let bytes = manifest.to_canonical_bytes()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(output);
        return Err(TreeError::Io(error));
    }
    Ok(manifest)
}

fn visit_directory(
    dir: &Dir,
    prefix: &str,
    files: &mut Vec<FileEntry>,
    total_bytes: &mut u64,
    encoded_budget: &mut usize,
    total_entries: &mut usize,
) -> Result<(), TreeError> {
    let initial_modified = dir.dir_metadata()?.modified().ok();
    for entry in dir.entries()? {
        let entry = entry?;
        count_tree_entry(total_entries)?;
        let name_os = entry.file_name();
        let name = name_os
            .to_str()
            .ok_or_else(|| TreeError::UnsupportedObject("non-UTF-8 filename".to_owned()))?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        manifest::validate_path(&path)?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(TreeError::UnsupportedObject(path));
        }
        if file_type.is_dir() {
            let child = dir.open_dir_nofollow(&name_os).map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidInput
                    || error.kind() == io::ErrorKind::NotADirectory
                {
                    TreeError::UnsupportedObject(path.clone())
                } else {
                    TreeError::Io(error)
                }
            })?;
            visit_directory(
                &child,
                &path,
                files,
                total_bytes,
                encoded_budget,
                total_entries,
            )?;
            continue;
        }
        if !file_type.is_file() {
            return Err(TreeError::UnsupportedObject(path));
        }
        if files.len() >= manifest::MAX_FILES {
            return Err(TreeError::ResourceLimit("100,000 file count"));
        }
        let mut options = CapOpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = dir.open_with(&name_os, &options).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidInput
                || error.kind() == io::ErrorKind::NotFound
            {
                TreeError::UnsupportedObject(path.clone())
            } else {
                TreeError::Io(error)
            }
        })?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(TreeError::UnsupportedObject(path));
        }
        let remaining = manifest::MAX_TOTAL_BYTES - *total_bytes;
        if before.len() > remaining {
            return Err(TreeError::ResourceLimit("1 TiB total file size"));
        }
        let mut bounded = file.take(remaining.saturating_add(1));
        let (digest, size) = hash::hash_reader_with_size(&mut bounded, hash::Algorithm::Sha256)
            .map_err(|error| TreeError::Io(io::Error::other(error.to_string())))?;
        let after = bounded.into_inner().metadata()?;
        if size > remaining {
            return Err(TreeError::ResourceLimit("1 TiB total file size"));
        }
        if size != before.len()
            || size != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(TreeError::Io(io::Error::other(format!(
                "file changed during scan: {path}"
            ))));
        }
        *total_bytes = total_bytes
            .checked_add(size)
            .ok_or(TreeError::ResourceLimit("1 TiB total file size"))?;
        let entry_cost = serde_json::to_vec(&FileEntry {
            path: path.clone(),
            size,
            digest: digest.clone(),
        })
        .map_err(|error| {
            TreeError::Manifest(ManifestError::Invalid(format!(
                "could not size manifest entry: {error}"
            )))
        })?
        .len();
        *encoded_budget = encoded_budget
            .saturating_add(entry_cost)
            .saturating_add(usize::from(!files.is_empty()));
        if *encoded_budget > manifest::MAX_MANIFEST_BYTES {
            return Err(TreeError::ResourceLimit("16 MiB manifest size"));
        }
        files.push(FileEntry { path, size, digest });
    }
    if initial_modified != dir.dir_metadata()?.modified().ok() {
        return Err(TreeError::Io(io::Error::other(format!(
            "directory changed during scan: {}",
            if prefix.is_empty() { "." } else { prefix }
        ))));
    }
    Ok(())
}

pub fn verify_directory(root: &Path, manifest: &Manifest) -> Result<VerificationReport, TreeError> {
    let root_dir = open_root(root)?;
    let expected: HashMap<&str, &FileEntry> = manifest
        .files
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut state = VerificationState {
        found: HashSet::with_capacity(expected.len()),
        expected,
        report: VerificationReport::default(),
        total_bytes: 0,
        actual_count: 0,
        total_entries: 0,
    };
    verify_directory_inner(&root_dir, "", &mut state)?;
    state.report.missing_files = state
        .expected
        .keys()
        .filter(|path| !state.found.contains(**path))
        .count() as u64;
    if state.report.is_verified() {
        Ok(state.report)
    } else {
        Err(TreeError::IntegrityMismatch(state.report))
    }
}

fn open_root(root: &Path) -> Result<Dir, TreeError> {
    let candidate = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let leaf = candidate.file_name();
    let candidate = if leaf.is_some_and(|name| name == "." || name == "..") {
        fs::canonicalize(candidate)?
    } else {
        candidate
    };
    let Some(name) = candidate.file_name() else {
        let root_dir = Dir::open_ambient_dir(&candidate, cap_std::ambient_authority())?;
        if !root_dir.dir_metadata()?.is_dir() {
            return Err(TreeError::UnsupportedObject(root.display().to_string()));
        }
        return Ok(root_dir);
    };
    let parent = candidate.parent().ok_or_else(|| {
        TreeError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root has no parent",
        ))
    })?;
    let parent_dir = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    let metadata = parent_dir.symlink_metadata(name)?;
    let is_link = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let is_link = {
        use cap_fs_ext::OsMetadataExt;
        is_link || metadata.file_attributes() & 0x400 != 0
    };
    if is_link || !metadata.is_dir() {
        return Err(TreeError::UnsupportedObject(root.display().to_string()));
    }
    let root_dir = parent_dir.open_dir_nofollow(name)?;
    if !root_dir.dir_metadata()?.is_dir() {
        return Err(TreeError::UnsupportedObject(root.display().to_string()));
    }
    Ok(root_dir)
}

fn verify_directory_inner(
    dir: &Dir,
    prefix: &str,
    state: &mut VerificationState<'_>,
) -> Result<(), TreeError> {
    let initial_modified = dir.dir_metadata()?.modified().ok();
    for entry in dir.entries()? {
        let entry = entry?;
        count_tree_entry(&mut state.total_entries)?;
        let name_os = entry.file_name();
        let name = name_os
            .to_str()
            .ok_or_else(|| TreeError::UnsupportedObject("non-UTF-8 filename".to_owned()))?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        manifest::validate_path(&path)?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(TreeError::UnsupportedObject(path));
        }
        if file_type.is_dir() {
            let child = dir.open_dir_nofollow(&name_os).map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidInput
                    || error.kind() == io::ErrorKind::NotADirectory
                {
                    TreeError::UnsupportedObject(path.clone())
                } else {
                    TreeError::Io(error)
                }
            })?;
            verify_directory_inner(&child, &path, state)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(TreeError::UnsupportedObject(path));
        }
        state.actual_count += 1;
        if state.actual_count > manifest::MAX_FILES {
            return Err(TreeError::ResourceLimit("100,000 file count"));
        }
        state.found.insert(path.clone());
        let Some(expected_entry) = state.expected.get(path.as_str()) else {
            state.report.unexpected_files += 1;
            continue;
        };
        let mut options = CapOpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = dir.open_with(&name_os, &options).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidInput
                || error.kind() == io::ErrorKind::NotFound
            {
                TreeError::UnsupportedObject(path.clone())
            } else {
                TreeError::Io(error)
            }
        })?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(TreeError::UnsupportedObject(path));
        }
        let remaining = manifest::MAX_TOTAL_BYTES - state.total_bytes;
        if before.len() > remaining {
            return Err(TreeError::ResourceLimit("1 TiB total file size"));
        }
        let mut bounded = file.take(remaining.saturating_add(1));
        let (digest, size) = hash::hash_reader_with_size(&mut bounded, hash::Algorithm::Sha256)
            .map_err(|error| TreeError::Io(io::Error::other(error.to_string())))?;
        let after = bounded.into_inner().metadata()?;
        if size > remaining {
            return Err(TreeError::ResourceLimit("1 TiB total file size"));
        }
        if size != before.len()
            || size != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(TreeError::Io(io::Error::other(format!(
                "file changed during verification: {path}"
            ))));
        }
        state.total_bytes = state
            .total_bytes
            .checked_add(size)
            .ok_or(TreeError::ResourceLimit("1 TiB total file size"))?;
        if size == expected_entry.size && digest == expected_entry.digest {
            state.report.matched_files += 1;
        } else {
            state.report.modified_files += 1;
        }
    }
    if initial_modified != dir.dir_metadata()?.modified().ok() {
        return Err(TreeError::Io(io::Error::other(format!(
            "directory changed during verification: {}",
            if prefix.is_empty() { "." } else { prefix }
        ))));
    }
    Ok(())
}

fn count_tree_entry(total: &mut usize) -> Result<(), TreeError> {
    *total = total
        .checked_add(1)
        .ok_or(TreeError::ResourceLimit("200,000 total directory entries"))?;
    if *total > MAX_TREE_ENTRIES {
        return Err(TreeError::ResourceLimit("200,000 total directory entries"));
    }
    Ok(())
}

pub fn output_is_inside_root(root: &Path, output: &Path) -> Result<bool, TreeError> {
    let canonical_root = fs::canonicalize(root)?;
    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(output_parent)?;
    let file_name = output.file_name().ok_or_else(|| {
        TreeError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output path has no filename",
        ))
    })?;
    let resolved_output: PathBuf = canonical_parent.join(file_name);
    #[cfg(windows)]
    {
        let root_text = canonical_root.to_str().ok_or_else(|| {
            TreeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot safely compare non-Unicode Windows output paths",
            ))
        })?;
        let output_text = resolved_output.to_str().ok_or_else(|| {
            TreeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot safely compare non-Unicode Windows output paths",
            ))
        })?;
        let root_lower = root_text.trim_end_matches(['\\', '/']).to_ascii_lowercase();
        let output_lower = output_text.to_ascii_lowercase();
        let prefix = format!("{root_lower}\\");
        Ok(output_lower == root_lower || output_lower.starts_with(&prefix))
    }
    #[cfg(not(windows))]
    {
        Ok(resolved_output.starts_with(canonical_root))
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TREE_ENTRIES, TreeError, count_tree_entry};

    #[test]
    fn enforces_total_directory_entry_limit() {
        let mut count = MAX_TREE_ENTRIES;
        assert!(matches!(
            count_tree_entry(&mut count),
            Err(TreeError::ResourceLimit(_))
        ));
        let mut overflow = usize::MAX;
        assert!(matches!(
            count_tree_entry(&mut overflow),
            Err(TreeError::ResourceLimit(_))
        ));
    }
}
