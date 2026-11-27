use serde::{Deserialize, Serialize};

pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FILES: usize = 100_000;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_PATH_DEPTH: usize = 64;
pub const MAX_TOTAL_BYTES: u64 = 1 << 40;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u8,
    pub algorithm: String,
    pub files: Vec<FileEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub digest: String,
}

#[derive(Debug)]
pub enum ManifestError {
    Invalid(String),
    Limit(&'static str),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Limit(limit) => write!(f, "manifest exceeds the {limit} limit"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl Manifest {
    pub fn new(mut files: Vec<FileEntry>) -> Result<Self, ManifestError> {
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let manifest = Self {
            version: 1,
            algorithm: "sha256".to_owned(),
            files,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|error| {
            ManifestError::Invalid(format!("could not encode manifest: {error}"))
        })?;
        bytes.push(b'\n');
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Limit("16 MiB serialized manifest size"));
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Limit("16 MiB input size"));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| ManifestError::Invalid(format!("malformed manifest JSON: {error}")))?;
        let canonical = manifest.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(ManifestError::Invalid(
                "manifest is not in canonical version 1 form".to_owned(),
            ));
        }
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        if self.version != 1 {
            return Err(ManifestError::Invalid(
                "unsupported manifest version".to_owned(),
            ));
        }
        if self.algorithm != "sha256" {
            return Err(ManifestError::Invalid(
                "unsupported manifest hash algorithm".to_owned(),
            ));
        }
        if self.files.len() > MAX_FILES {
            return Err(ManifestError::Limit("100,000 file count"));
        }

        let mut previous: Option<&str> = None;
        let mut portable_paths = std::collections::HashSet::with_capacity(self.files.len());
        let mut encoded_size = 46usize;
        let mut total_bytes = 0u64;
        for entry in &self.files {
            validate_path(&entry.path)?;
            if entry.digest.len() != 64
                || !entry
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ManifestError::Invalid(
                    "file digest must be 64 lowercase hexadecimal characters".to_owned(),
                ));
            }
            if previous.is_some_and(|path| path.as_bytes() >= entry.path.as_bytes()) {
                return Err(ManifestError::Invalid(
                    "manifest paths must be strictly sorted by UTF-8 bytes".to_owned(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(entry.size)
                .filter(|total| *total <= MAX_TOTAL_BYTES)
                .ok_or(ManifestError::Limit("1 TiB total file size"))?;
            let collision_key = entry.path.to_ascii_lowercase();
            if !portable_paths.insert(collision_key) {
                return Err(ManifestError::Invalid(
                    "manifest contains duplicate or case-colliding paths".to_owned(),
                ));
            }
            let row_size = serde_json::to_vec(entry)
                .map_err(|error| {
                    ManifestError::Invalid(format!("could not size manifest entry: {error}"))
                })?
                .len();
            encoded_size = encoded_size
                .saturating_add(row_size)
                .saturating_add(usize::from(previous.is_some()));
            if encoded_size > MAX_MANIFEST_BYTES {
                return Err(ManifestError::Limit("16 MiB serialized manifest size"));
            }
            previous = Some(&entry.path);
        }
        Ok(())
    }
}

pub fn validate_path(path: &str) -> Result<(), ManifestError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(ManifestError::Invalid(
            "manifest path is empty or exceeds 1,024 bytes".to_owned(),
        ));
    }
    if !path.is_ascii()
        || path
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._-/".contains(&byte)))
    {
        return Err(ManifestError::Invalid(
            "manifest paths must use portable ASCII letters, digits, '.', '_', '-', and '/'"
                .to_owned(),
        ));
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_PATH_DEPTH {
        return Err(ManifestError::Limit("64 path component depth"));
    }
    for component in components {
        if component.is_empty() || component == "." || component == ".." || component.ends_with('.')
        {
            return Err(ManifestError::Invalid(
                "manifest path contains an empty, dot, parent, or trailing-dot component"
                    .to_owned(),
            ));
        }
        let basename = component.split('.').next().unwrap_or(component);
        let uppercase = basename.to_ascii_uppercase();
        if matches!(
            uppercase.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (uppercase.len() == 4
            && (uppercase.starts_with("COM") || uppercase.starts_with("LPT"))
            && matches!(uppercase.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(ManifestError::Invalid(
                "manifest path contains a Windows reserved device name".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FileEntry, MAX_FILES, MAX_MANIFEST_BYTES, MAX_PATH_BYTES, MAX_PATH_DEPTH, MAX_TOTAL_BYTES,
        Manifest, ManifestError, validate_path,
    };

    fn entry(path: &str) -> FileEntry {
        FileEntry {
            path: path.to_owned(),
            size: 0,
            digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        }
    }

    #[test]
    fn empty_manifest_has_one_canonical_encoding() {
        let manifest = Manifest::new(Vec::new()).unwrap();
        assert_eq!(
            manifest.to_canonical_bytes().unwrap(),
            b"{\"version\":1,\"algorithm\":\"sha256\",\"files\":[]}\n"
        );
        assert_eq!(
            Manifest::parse(&manifest.to_canonical_bytes().unwrap()).unwrap(),
            manifest
        );
    }

    #[test]
    fn sorts_paths_using_utf8_byte_order() {
        let manifest = Manifest::new(vec![entry("z"), entry("a")]).unwrap();
        assert_eq!(manifest.files[0].path, "a");
        assert_eq!(manifest.files[1].path, "z");
    }

    #[test]
    fn rejects_ambiguous_json_and_case_colliding_paths() {
        assert!(
            Manifest::parse(br#"{"version":1,"version":1,"algorithm":"sha256","files":[]}"#)
                .is_err()
        );
        assert!(matches!(
            Manifest::new(vec![entry("Readme"), entry("README")]),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_noncanonical_json_and_unknown_fields() {
        assert!(Manifest::parse(br#"{ "version":1,"algorithm":"sha256","files":[]}"#).is_err());
        assert!(
            Manifest::parse(br#"{"version":1,"algorithm":"sha256","files":[],"extra":true}"#)
                .is_err()
        );
    }

    #[test]
    fn rejects_unsafe_and_nonportable_paths() {
        for path in [
            "../escape",
            "/absolute",
            "a//b",
            "a/./b",
            "CON.txt",
            "COM1.log",
            "name.",
            "caf\u{e9}",
        ] {
            assert!(validate_path(path).is_err(), "accepted {path:?}");
        }
        validate_path("dist/bin/seal.exe").unwrap();
    }

    #[test]
    fn enforces_path_depth_length_file_count_and_total_size() {
        assert!(validate_path(&"a".repeat(MAX_PATH_BYTES + 1)).is_err());
        let too_deep = format!("{}a", "a/".repeat(MAX_PATH_DEPTH));
        assert!(validate_path(&too_deep).is_err());
        assert!(matches!(
            Manifest::new(vec![entry("a"); MAX_FILES + 1]),
            Err(ManifestError::Limit(_))
        ));

        let mut first = entry("a");
        first.size = MAX_TOTAL_BYTES;
        let mut second = entry("b");
        second.size = 1;
        assert!(matches!(
            Manifest::new(vec![first, second]),
            Err(ManifestError::Limit(_))
        ));
    }

    #[test]
    fn rejects_oversized_manifest_input_before_parsing() {
        assert!(matches!(
            Manifest::parse(&vec![b' '; MAX_MANIFEST_BYTES + 1]),
            Err(ManifestError::Limit(_))
        ));
    }
}
