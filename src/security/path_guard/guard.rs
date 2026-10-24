use super::{
    constants::{CTRL_RE, MAX_PATH_LEN},
    glob::GlobSet,
    rel::Rel,
    resolved::ResolvedPath,
    root::Root,
    windows::{is_windows_drive_path, windows_path_check},
};
use crate::config::models::permissions::FsCfg;
use crate::error::{Error, Result, SecResult, SecurityError};
use crate::util::{abspath, case_insensitive_fs, expanduser, is_under, realpath};
use std::fs::symlink_metadata;
use std::path::{Path, PathBuf};

pub struct PathGuard {
    pub roots: Vec<Root>,
    deny: GlobSet,
    deny_exc: GlobSet,
    write_deny: GlobSet,
    pub cfg: FsCfg,
}

impl PathGuard {
    pub fn new(cfg: &FsCfg) -> Result<PathGuard> {
        let mut roots = Vec::new();

        for root_cfg in &cfg.roots {
            let path = expanduser(&root_cfg.path);

            if !path.is_dir() {
                return Err(Error::config(format!(
                    "root doesn't exist or isn't a folder : {}",
                    root_cfg.path
                )));
            }

            let real = realpath(&path);
            if real.parent().is_none() {
                return Err(Error::config("the root '/' is forbidden as perimeter"));
            }

            if is_windows_drive_path(&real) && !cfg.allow_windows_drives {
                return Err(Error::config(format!("root '{}' on a Windows disk mounted (/mnt/<lettre>) : refused (links, permissions and inodes haven't the Linux's semantic, and the Windows disk is out of the sandbox). Use the Linux filesystem (ex. ~/workspace) or fs.allow_windows_drives=true with the knowed risks.", root_cfg.path)));
            }

            roots.push(Root {
                name: root_cfg.name.clone(),
                path: real,
                write: root_cfg.write,
            });
        }

        Ok(PathGuard {
            roots,
            deny: GlobSet::new(&cfg.deny_globs),
            deny_exc: GlobSet::new(&cfg.deny_exceptions),
            write_deny: GlobSet::new(&cfg.write_deny_globs),
            cfg: cfg.clone(),
        })
    }

    pub fn default_root(&self) -> &Root {
        &self.roots[0]
    }

    /// Raw deny-glob hit (no exception, no `.git` rule): used where the Python original applied `deny_globs` alone.
    pub fn deny_hit(&self, rel: &Rel) -> bool {
        self.deny.first_match(rel).is_some()
    }

    pub fn deny_globs(&self) -> &[String] {
        self.deny.patterns()
    }

    pub fn deny_exceptions(&self) -> &[String] {
        &self.cfg.deny_exceptions
    }

    fn sanitize<'a>(&self, raw: &'a str) -> SecResult<&'a str> {
        if raw.trim().is_empty() {
            return Err(SecurityError::path("empty_path", "empty path"));
        }

        if raw.len() > MAX_PATH_LEN {
            return Err(SecurityError::path("path_too_long", "too long path"));
        }

        if CTRL_RE.is_match(raw) {
            return Err(SecurityError::path(
                "control_chars",
                "CTRL found in the path",
            ));
        }

        if raw.split(['\\', '/']).any(|p| p == "..") {
            return Err(SecurityError::path(
                "path_traversal",
                "component '..' is forbidden",
            ));
        }

        if raw.contains('\\') {
            return Err(SecurityError::path(
                "backslash",
                "backslash forbidden in the paths",
            ));
        }

        if cfg!(windows) {
            windows_path_check(raw)?;
        }

        Ok(raw)
    }

    pub fn root_of(&self, real: &Path) -> Option<&Root> {
        self.roots.iter().find(|root| is_under(real, &root.path))
    }

    /// True (and why) when `rel` is hard-denied (.git) or matched by a deny glob without matching an exception.
    pub fn denied_by_policy(&self, rel: &Rel) -> Option<SecurityError> {
        let ci = case_insensitive_fs();

        if rel.parts().iter().any(|part| {
            if ci {
                part.eq_ignore_ascii_case(".git")
            } else {
                part == ".git"
            }
        }) {
            return Some(SecurityError::path(
                "git_internal_path",
                "the intern .git files are not allowed for the file tools",
            ));
        }

        self.deny
            .first_match(rel)
            .filter(|_| self.deny_exc.first_match(rel).is_none())
            .map(|hit| {
                SecurityError::path(
                    "denied_by_pattern",
                    format!("file protected by the policy ({hit})"),
                )
            })
    }

    /// Cheap variant for entries discovered while walking an already-resolved directory without following links
    /// (real path == lexical path): no `realpath` needed.
    pub fn check_discovered(
        &self,
        base: &ResolvedPath,
        relative_parts: &[String],
    ) -> SecResult<Rel> {
        let mut parts = base.rel.0.clone();
        parts.extend_from_slice(relative_parts);
        let rel = Rel(parts);
        match self.denied_by_policy(&rel) {
            Some(e) => Err(e),
            None => Ok(rel),
        }
    }

    /// `access`: "read" | "write". `base`: directory (already validated) used for relative paths; default: first root.
    pub fn resolve(&self, raw: &str, access: &str, base: Option<&Path>) -> SecResult<ResolvedPath> {
        assert!(
            access == "read" || access == "write",
            "access should be 'read' or 'write'"
        );

        let raw = self.sanitize(raw)?;
        let start = base.unwrap_or(&self.default_root().path);
        let cand = if raw.starts_with('~') {
            expanduser(raw)
        } else {
            PathBuf::from(raw)
        };

        if cfg!(windows) {
            use std::path::Component;
            let mut it = cand.components();
            if matches!(it.next(), Some(Component::Prefix(_))) && !cand.has_root() {
                return Err(SecurityError::path(
                    "drive_relative",
                    "relative path to a disk (C:file) forbidden",
                ));
            }
        }

        let lexical = abspath(&if cand.is_absolute() {
            cand
        } else {
            start.join(cand)
        });

        let real = realpath(&lexical);
        let root = self
            .root_of(&real)
            .ok_or_else(|| {
                SecurityError::path(
                    "outside_allowed_roots",
                    "path is out of the authorized directories",
                )
            })?
            .clone();

        let rel = Rel::from_path(&real, &root.path);
        let lex_root = self.root_of(&lexical).cloned();

        let lex_rel = lex_root
            .as_ref()
            .map(|root| Rel::from_path(&lexical, &root.path))
            .unwrap_or_else(|| rel.clone());
        let mut seen: Vec<&Rel> = vec![&rel];

        if lex_rel != rel {
            seen.push(&lex_rel);
        }

        for rel in &seen {
            if let Some(e) = self.denied_by_policy(rel) {
                return Err(e);
            }
        }

        if access == "write" {
            if !root.write {
                return Err(SecurityError::path(
                    "root_read_only",
                    format!("the root '{}' is in read-only mode", root.name),
                ));
            }

            for rel in &seen {
                if let Some(hit) = self.write_deny.first_match(rel) {
                    return Err(SecurityError::path(
                        "write_denied_by_pattern",
                        format!("write unauthorized by the policy ({hit})"),
                    ));
                }
            }
            Self::assert_no_symlink(&lexical, lex_root.as_ref().unwrap_or(&root))?;
        }

        Ok(ResolvedPath {
            real,
            lexical,
            root,
            rel,
        })
    }

    pub fn read(&self, raw: &str) -> SecResult<ResolvedPath> {
        self.resolve(raw, "read", None)
    }

    pub fn write(&self, raw: &str) -> SecResult<ResolvedPath> {
        self.resolve(raw, "write", None)
    }

    fn assert_no_symlink(lexical: &Path, root: &Root) -> SecResult<()> {
        let tail = lexical
            .strip_prefix(&root.path)
            .map_err(|_| SecurityError::path("symlink_escape", "lexical path out of the root"))?;
        let mut cur = root.path.clone();

        for part in tail.components() {
            cur.push(part);
            if symlink_metadata(&cur)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(SecurityError::path(
                    "symlink_in_path",
                    "write across a forbidden symlink",
                ));
            }
        }
        Ok(())
    }
}
