//! Reclaim policy: when a literal deletion removes only disposable data.
//!
//! Agents on disk-constrained machines must be able to clear their own temp
//! output, updater caches and regenerable build output without a person
//! approving each `rm -rf`. A deletion target qualifies only when it is a
//! static absolute path (or `~/` followed by one) with no expansion, glob,
//! `.` or `..` component, and its real location after following every
//! symlink is one of:
//!
//! - below a temp root (`/tmp`, `/var/tmp`, their macOS `/private` forms, the
//!   startup `TMPDIR`, or the macOS per-user temp directory `TMPDIR` names),
//!   never the root itself;
//! - below `~/Library/Caches`, never the cache root itself;
//! - a build-output directory (`node_modules`, `dist`, `.next`, `coverage`,
//!   `target`, `build`) that is a real directory without `.git`, sits next to
//!   a project manifest, and lies at least two levels below the home
//!   directory.
//!
//! The part of the path below its trusted root must survive symlink
//! resolution unchanged ([`crate::path_proof`]), so a link inside a temp dir
//! that points at the home directory grants nothing. Inside a remote script
//! the local filesystem proves nothing, so nothing qualifies there.

use std::path::{Path, PathBuf};

const TEMP_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"];

const BUILD_OUTPUT_NAMES: &[&str] = &[
    "node_modules",
    "dist",
    ".next",
    "coverage",
    "target",
    "build",
];

const PROJECT_MANIFESTS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "setup.py",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "deno.json",
    "CMakeLists.txt",
];

/// Characters a deletion operand may contain and still name exactly the path
/// it spells: no quoting, expansion, glob, escape or separator syntax.
fn is_literal_path_char(character: char) -> bool {
    !character.is_ascii()
        || character.is_ascii_alphanumeric()
        || matches!(
            character,
            '/' | '.' | '_' | '-' | '+' | ',' | '@' | '%' | ':' | '='
        )
}

/// Decode one unquoted deletion operand into the absolute path it names.
///
/// Accepts an absolute path or `~/` followed by a relative one. Returns
/// `None` for anything the shell could turn into a different path: quotes,
/// variables, globs, braces, escapes, `~user`, and `.` or `..` components.
#[must_use]
pub(crate) fn literal_absolute_operand(word: &str, home: &Path) -> Option<PathBuf> {
    let (body, path) = if let Some(rest) = word.strip_prefix("~/") {
        (rest, home.join(rest))
    } else if word.starts_with('/') {
        (word, PathBuf::from(word))
    } else {
        return None;
    };
    if body.is_empty()
        || !body.chars().all(is_literal_path_char)
        || body
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return None;
    }
    Some(path)
}

thread_local! {
    static SUSPENDED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// While alive, no deletion qualifies under this policy on this thread.
///
/// The policy requires every operand to be spelled literally in the command.
/// The `$VAR` proof (#396) re-runs the `rm` classifier on text with proven
/// values spliced in; that text was never spelled by the caller, so the proof
/// suspends the policy for its run.
pub(crate) struct ReclaimSuspended {
    previous: bool,
}

impl ReclaimSuspended {
    #[must_use]
    pub(crate) fn enter() -> Self {
        Self {
            previous: SUSPENDED.with(|suspended| suspended.replace(true)),
        }
    }
}

impl Drop for ReclaimSuspended {
    fn drop(&mut self) {
        SUSPENDED.with(|suspended| suspended.set(self.previous));
    }
}

/// The roots the reclaim policy trusts: the home directory and the temp
/// roots. Tests build their own so fixtures never sit under a real temp root.
pub(crate) struct ReclaimRoots {
    home: PathBuf,
    temp_roots: Vec<PathBuf>,
}

impl ReclaimRoots {
    /// The caller's home directory plus `/tmp`, `/var/tmp`, their `/private`
    /// forms, the startup `TMPDIR` and the macOS per-user temp directory.
    /// `None` without a usable home, and while [`ReclaimSuspended`] is in
    /// force.
    #[must_use]
    pub(crate) fn current() -> Option<Self> {
        if SUSPENDED.with(std::cell::Cell::get) {
            return None;
        }
        let home = crate::config::home_dir()?;
        let per_user = std::env::var_os("TMPDIR")
            .map(|tmpdir| per_user_temp_roots(&tmpdir, &home))
            .unwrap_or_default();
        let temp_roots = TEMP_ROOTS
            .iter()
            .copied()
            .chain(crate::evaluator::startup_tmpdir_root())
            .map(PathBuf::from)
            .chain(per_user)
            .collect();
        Some(Self { home, temp_roots })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    /// Whether deleting `path` (already decoded and absolute) removes only
    /// disposable data under the policy described in the module docs.
    #[must_use]
    pub(crate) fn path_is_reclaimable(&self, path: &Path) -> bool {
        if crate::evaluator::nonlocal_filesystem_scope_active() || !path.is_absolute() {
            return false;
        }
        let canonical_home =
            std::fs::canonicalize(&self.home).unwrap_or_else(|_| self.home.clone());
        // A home directory at the filesystem root scopes nothing.
        if canonical_home.parent().is_none() {
            return false;
        }
        // A temp root that holds the home directory (a test sandbox, an odd
        // HOME) does not make the home tree scratch: inside home only the
        // cache and build-output rules apply.
        let inside_home = crate::path_proof::resolve_through_existing_ancestor(path)
            .is_none_or(|real| real.starts_with(&canonical_home));
        (!inside_home
            && self
                .temp_roots
                .iter()
                .any(|root| strictly_below_root(path, root)))
            || strictly_below_root(path, &self.home.join("Library/Caches"))
            || is_project_build_output(path, &self.home)
    }

    /// Decode `word` and judge the path it names.
    #[must_use]
    pub(crate) fn operand_is_reclaimable(&self, word: &str) -> bool {
        literal_absolute_operand(word, &self.home)
            .is_some_and(|path| self.path_is_reclaimable(&path))
    }

    /// Whether `command` is exactly one `find` invocation that deletes below
    /// reclaimable start paths, with no option or predicate that could widen
    /// it.
    ///
    /// The accepted shape is `find <path>... [-mindepth N] [-maxdepth N]
    /// [-type f|d|l] [-xdev|-mount|-depth] -delete`. Any other text (a second
    /// command, `-L`, `-exec`, `-name` patterns, quoting, variables) is
    /// refused, so the find-delete rules keep their verdict.
    #[must_use]
    pub(crate) fn find_delete_command_is_reclaimable(&self, command: &str) -> bool {
        let command = command.trim();
        if command.contains(|character: char| {
            matches!(
                character,
                '\n' | '\r'
                    | ';'
                    | '|'
                    | '&'
                    | '$'
                    | '`'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '\\'
                    | '\''
                    | '"'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '#'
            )
        }) {
            return false;
        }
        let mut words = command.split_ascii_whitespace();
        if !matches!(words.next(), Some("find" | "/usr/bin/find" | "/bin/find")) {
            return false;
        }
        let words: Vec<&str> = words.collect();
        let operand_count = words
            .iter()
            .take_while(|word| !word.starts_with('-'))
            .count();
        let (operands, expression) = words.split_at(operand_count);
        if operands.is_empty()
            || !operands
                .iter()
                .all(|word| self.operand_is_reclaimable(word))
        {
            return false;
        }
        let Some((&"-delete", mut predicates)) = expression.split_last() else {
            return false;
        };
        while let Some((&first, tail)) = predicates.split_first() {
            predicates = match (first, tail.split_first()) {
                ("-mindepth" | "-maxdepth", Some((depth, rest)))
                    if depth.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    rest
                }
                ("-type", Some((&("f" | "d" | "l"), rest))) => rest,
                ("-xdev" | "-mount" | "-depth", _) => tail,
                _ => return false,
            };
        }
        true
    }
}

/// The macOS per-user temp directory, when `tmpdir` names it.
///
/// macOS gives each user a private `/var/folders/<a>/<b>/T` and exports it as
/// `TMPDIR`; `mktemp -d` and most tools put their scratch there. The startup
/// `TMPDIR` check refuses it, because `/var` is a protected system tree in
/// general, so only this exact shape is accepted here: it must resolve to
/// `/private/var/folders/<a>/<b>/T`, be a directory, and belong to the owner
/// of the home directory. Both spellings are returned so a target written
/// either way matches.
fn per_user_temp_roots(tmpdir: &std::ffi::OsStr, home: &Path) -> Vec<PathBuf> {
    use std::path::Component;

    let spelled = Path::new(tmpdir);
    let mut components = spelled.components();
    if components.next() != Some(Component::RootDir) {
        return Vec::new();
    }
    let Some(names) = components
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<&str>>>()
    else {
        return Vec::new();
    };
    let tail = names.strip_prefix(&["private"]).unwrap_or(names.as_slice());
    let ["var", "folders", bucket, user, "T"] = tail else {
        return Vec::new();
    };
    let short = Path::new("/var/folders").join(bucket).join(user).join("T");
    let real = Path::new("/private/var/folders")
        .join(bucket)
        .join(user)
        .join("T");
    let owned_by_home_owner = std::fs::metadata(&real)
        .ok()
        .zip(std::fs::metadata(home).ok())
        .is_some_and(|(temp, home)| temp.is_dir() && same_owner(&temp, &home));
    if !owned_by_home_owner || std::fs::canonicalize(spelled).ok().as_ref() != Some(&real) {
        return Vec::new();
    }
    vec![short, real]
}

#[cfg(unix)]
fn same_owner(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    first.uid() == second.uid()
}

#[cfg(not(unix))]
fn same_owner(_first: &std::fs::Metadata, _second: &std::fs::Metadata) -> bool {
    false
}

/// `path` is spelled below `root`, is not `root` itself, and lands there.
fn strictly_below_root(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root)
        .is_ok_and(|suffix| suffix.components().next().is_some())
        && crate::path_proof::spelled_suffix_survives_resolution(path, root)
}

fn is_project_build_output(path: &Path, home: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !BUILD_OUTPUT_NAMES.contains(&name) {
        return false;
    }
    // `~/app/node_modules` at the shallowest: the project directory itself
    // must not be the home directory.
    if !path
        .strip_prefix(home)
        .is_ok_and(|suffix| suffix.components().count() >= 2)
    {
        return false;
    }
    // A real directory, not a symlink to one, that is not itself a checkout.
    if !std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
        || std::fs::symlink_metadata(path.join(".git")).is_ok()
    {
        return false;
    }
    let Some(project) = path.parent() else {
        return false;
    };
    PROJECT_MANIFESTS
        .iter()
        .any(|manifest| project.join(manifest).is_file())
        && crate::path_proof::spelled_suffix_survives_resolution(path, home)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _temp: tempfile::TempDir,
        roots: ReclaimRoots,
    }

    impl Fixture {
        fn home(&self) -> &Path {
            self.roots.home()
        }

        fn temp_root(&self) -> &Path {
            &self.roots.temp_roots[0]
        }

        /// `HOME` and `TMP` in `word` stand for the fixture's home and temp
        /// root, so the cases read like the commands they model.
        fn reclaimable(&self, word: &str) -> bool {
            let spelled = word
                .replace("HOME", &self.home().to_string_lossy())
                .replace("TMP", &self.temp_root().to_string_lossy());
            self.roots.operand_is_reclaimable(&spelled)
        }
    }

    /// A fake home with a project that has build output, a cache tree, a fake
    /// temp root, and the traps every rule must refuse. Nothing here sits
    /// under a temp root the fixture does not declare, so the real `/tmp`
    /// and `TMPDIR` cannot make a negative case pass by accident.
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().expect("temp");
        let home = temp.path().join("home");
        let temp_root = temp.path().join("tmp");
        for dir in [
            "code/app/node_modules/pkg",
            "code/app/dist",
            "code/app/src",
            "code/bare/node_modules",
            "code/repo-named-build/build/.git",
            "Library/Caches/com.example.app/Data",
            ".config/tool",
        ] {
            std::fs::create_dir_all(home.join(dir)).expect("fixture dir");
        }
        std::fs::create_dir_all(temp_root.join("session/out")).expect("temp tree");
        std::fs::write(home.join("code/app/package.json"), b"{}").expect("manifest");
        std::fs::write(home.join("code/repo-named-build/Cargo.toml"), b"").expect("manifest");
        symlink(&home, home.join("code/app/link-home")).expect("escape link");
        symlink(home.join("code"), home.join("Library/Caches/escape")).expect("cache escape");
        symlink(&home, temp_root.join("session/link-home")).expect("temp escape");
        Fixture {
            _temp: temp,
            roots: ReclaimRoots {
                home,
                temp_roots: vec![temp_root],
            },
        }
    }

    #[test]
    fn build_output_next_to_a_manifest_is_reclaimable() {
        let fixture = fixture();
        assert!(fixture.reclaimable("HOME/code/app/node_modules"));
        assert!(fixture.reclaimable("HOME/code/app/node_modules/"));
        assert!(fixture.reclaimable("HOME/code/app/dist"));
        assert!(fixture.reclaimable("~/code/app/node_modules"));
    }

    #[test]
    fn build_output_names_without_a_project_are_not_reclaimable() {
        let fixture = fixture();
        // No manifest next to it.
        assert!(!fixture.reclaimable("HOME/code/bare/node_modules"));
        // A checkout that happens to be called `build`.
        assert!(!fixture.reclaimable("HOME/code/repo-named-build/build"));
        // Not a build-output name.
        assert!(!fixture.reclaimable("HOME/code/app/src"));
        // Missing: nothing proves it is build output.
        assert!(!fixture.reclaimable("HOME/code/app/coverage"));
        // The project, the home directory and its parent.
        assert!(!fixture.reclaimable("HOME/code/app"));
        assert!(!fixture.reclaimable("HOME"));
        assert!(!fixture.reclaimable("HOME/"));
        assert!(!fixture.reclaimable("HOME/code/app/node_modules/.."));
    }

    #[test]
    fn a_symlink_named_like_build_output_is_not_reclaimable() {
        let fixture = fixture();
        symlink(
            fixture.home().join("code/app/src"),
            fixture.home().join("code/app/build"),
        )
        .expect("build link");
        assert!(!fixture.reclaimable("HOME/code/app/build"));
        assert!(!fixture.reclaimable("HOME/code/app/build/"));
        // A path that reaches build output through a link is refused too.
        assert!(!fixture.reclaimable("HOME/code/app/link-home/code/app/node_modules"));
    }

    #[test]
    fn caches_below_the_cache_root_are_reclaimable() {
        let fixture = fixture();
        assert!(fixture.reclaimable("HOME/Library/Caches/com.example.app"));
        assert!(fixture.reclaimable("HOME/Library/Caches/com.example.app/Data"));
        assert!(fixture.reclaimable("~/Library/Caches/com.example.app"));
    }

    #[test]
    fn the_cache_root_and_escapes_from_it_are_not_reclaimable() {
        let fixture = fixture();
        assert!(!fixture.reclaimable("HOME/Library/Caches"));
        assert!(!fixture.reclaimable("HOME/Library/Caches/"));
        assert!(!fixture.reclaimable("~/Library/Caches"));
        assert!(!fixture.reclaimable("HOME/Library"));
        assert!(!fixture.reclaimable("HOME/Library/Caches/escape"));
        assert!(!fixture.reclaimable("HOME/Library/Caches/escape/"));
        assert!(!fixture.reclaimable("HOME/Library/Caches/escape/app"));
        assert!(!fixture.reclaimable("HOME/Library/Caches/../Preferences"));
        assert!(!fixture.reclaimable("HOME/Library/Caches/./x"));
    }

    #[test]
    fn temp_children_are_reclaimable_but_not_the_root_or_escapes() {
        let fixture = fixture();
        assert!(fixture.reclaimable("TMP/session"));
        assert!(fixture.reclaimable("TMP/session/out"));
        assert!(fixture.reclaimable("TMP/session/not-yet-created"));
        for refused in [
            "TMP",
            "TMP/",
            "TMP/session/link-home",
            "TMP/session/link-home/",
            "TMP/session/link-home/code",
            "TMP/session/../..",
            "/",
            "/etc",
            "/usr/local",
        ] {
            assert!(!fixture.reclaimable(refused), "{refused}");
        }
    }

    #[test]
    fn the_real_temp_roots_are_never_reclaimable_themselves() {
        let Some(roots) = ReclaimRoots::current() else {
            return;
        };
        for root in [
            "/tmp",
            "/tmp/",
            "/var/tmp",
            "/private/tmp",
            "/private/var/tmp/",
        ] {
            assert!(!roots.operand_is_reclaimable(root), "{root}");
        }
    }

    #[test]
    fn dynamic_and_relative_operands_are_never_decoded() {
        let home = Path::new("/home/someone");
        for word in [
            "$HOME/Library/Caches/x",
            "${HOME}/x",
            "\"/tmp/x\"",
            "'/tmp/x'",
            "/tmp/*",
            "/tmp/x?",
            "/tmp/{a,b}",
            "/tmp/a\\ b",
            "~other/x",
            "~",
            "relative/node_modules",
            "./node_modules",
            "/tmp/../etc",
            "/tmp/./x",
            "`pwd`/x",
        ] {
            assert!(literal_absolute_operand(word, home).is_none(), "{word}");
        }
    }

    #[test]
    fn nothing_is_reclaimable_inside_a_remote_script() {
        let fixture = fixture();
        let path = fixture.home().join("code/app/node_modules");
        assert!(fixture.roots.path_is_reclaimable(&path));
        crate::evaluator::with_nonlocal_filesystem_scope_for_test(|| {
            assert!(!fixture.roots.path_is_reclaimable(&path));
        });
    }

    #[test]
    fn find_delete_accepts_only_the_narrow_shape() {
        let fixture = fixture();
        let app = fixture
            .home()
            .join("code/app/node_modules")
            .to_string_lossy()
            .into_owned();
        let cache = "~/Library/Caches/com.example.app";
        let allowed = |command: &str| fixture.roots.find_delete_command_is_reclaimable(command);

        assert!(allowed(&format!("find {app} -mindepth 1 -delete")));
        assert!(allowed(&format!("find {app} -delete")));
        assert!(allowed(&format!(
            "find {cache} -mindepth 1 -type f -delete"
        )));
        assert!(allowed(&format!(
            "find {app} {cache} -maxdepth 3 -xdev -delete"
        )));

        for refused in [
            // A start path that is not reclaimable.
            format!("find {app} {} -delete", fixture.home().display()),
            format!("find {app} /etc -delete"),
            "find ~/Library/Caches -mindepth 1 -delete".to_string(),
            // Options and predicates that widen or hide the deletion.
            format!("find -L {app} -delete"),
            format!("find {app} -name '*.js' -delete"),
            format!("find {app} -newer /etc/passwd -delete"),
            format!("find {app} -exec rm -rf {{}} +"),
            format!("find {app} -delete -print"),
            format!("find {app} -mindepth x -delete"),
            format!("find {app}"),
            // Compound commands, expansion and wrappers.
            format!("find {app} -delete; rm -rf ~"),
            format!("find {app} -delete && echo ok"),
            format!("find {app} -delete\nrm -rf ~"),
            "find $HOME/Library/Caches/x -delete".to_string(),
            format!("sudo find {app} -delete"),
        ] {
            assert!(!allowed(&refused), "{refused}");
        }
    }

    #[test]
    fn only_the_exact_per_user_temp_shape_names_a_temp_root() {
        let home = tempfile::tempdir().expect("home");
        for spelled in [
            "/var/folders/ab/cd/C",
            "/var/folders/ab/T",
            "/var/folders/ab/cd/T/x",
            "/var/folders/ab/../cd/T",
            "var/folders/ab/cd/T",
            "/tmp/var/folders/ab/cd/T",
            "/var/tmp",
            "/",
            "",
        ] {
            assert!(
                per_user_temp_roots(std::ffi::OsStr::new(spelled), home.path()).is_empty(),
                "{spelled}"
            );
        }
    }

    /// On macOS the real `TMPDIR` is the per-user directory, so the shape
    /// check meets real directories: the directory itself qualifies in both
    /// spellings, while its existing siblings and traversal spellings do not.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_per_user_temp_directory_is_a_temp_root() {
        let tmpdir = std::env::var_os("TMPDIR").expect("macOS exports TMPDIR");
        let home = std::env::var_os("HOME").expect("HOME");
        let home = Path::new(&home);
        let roots = per_user_temp_roots(&tmpdir, home);
        let real = std::fs::canonicalize(&tmpdir).expect("TMPDIR resolves");
        assert!(roots.contains(&real), "{roots:?}");
        assert!(
            roots.iter().any(|root| root.starts_with("/var/folders")),
            "{roots:?}"
        );
        let bucket = real.parent().expect("per-user bucket");
        let cache = bucket.join("C");
        assert!(per_user_temp_roots(cache.as_os_str(), home).is_empty());
        let traversal = bucket.join("T/../T");
        assert!(per_user_temp_roots(traversal.as_os_str(), home).is_empty());
    }
}
