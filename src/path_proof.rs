//! Filesystem proofs for literal paths that a rule wants to trust.
//!
//! A lexical check on a path (`/tmp/x`, a glob such as `~/scratch/**`) says
//! where the path is spelled, not where it lands. A symlink anywhere below the
//! trusted root can send the same spelling into the home directory or a
//! system tree. The helpers here resolve both the trusted root and the target
//! through the filesystem and accept the target only when the part below the
//! root survives resolution unchanged.

use std::path::{Path, PathBuf};

/// Resolve `path` through its deepest existing ancestor.
///
/// The existing part is canonicalised (every symlink followed); the missing
/// tail is appended as spelled, since a component that does not exist cannot
/// be a symlink. A dangling symlink counts as existing and fails to
/// canonicalise, so it yields `None`, as does any error other than "not
/// found" (for example a regular file used as a directory).
#[must_use]
pub(crate) fn resolve_through_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(existing.file_name()?);
                existing = existing.parent()?;
            }
            Err(_) => return None,
        }
    }
    let mut resolved = std::fs::canonicalize(existing).ok()?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Some(resolved)
}

/// Whether `target`, spelled below `root`, really lands at the same place
/// below `root` once every symlink is followed.
///
/// Symlinks at or above `root` (`/tmp -> /private/tmp`) resolve the same way
/// on both sides and do not matter. A symlink below `root` that changes where
/// the target lands (`/tmp/x/link -> ~`) makes this false, as does a target
/// that is itself a symlink: a truncating redirect and `rm -rf link/` both
/// follow it. Both paths must be absolute.
#[must_use]
pub(crate) fn spelled_suffix_survives_resolution(target: &Path, root: &Path) -> bool {
    if !target.is_absolute() || !root.is_absolute() {
        return false;
    }
    let Ok(spelled_suffix) = target.strip_prefix(root) else {
        return false;
    };
    let (Some(real_target), Some(real_root)) = (
        resolve_through_existing_ancestor(target),
        resolve_through_existing_ancestor(root),
    ) else {
        return false;
    };
    real_target.strip_prefix(&real_root) == Ok(spelled_suffix)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_plain_path_below_the_root_survives() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir_all(root.path().join("a/b")).expect("tree");
        assert!(spelled_suffix_survives_resolution(
            &root.path().join("a/b"),
            root.path()
        ));
        // A missing tail is appended as spelled.
        assert!(spelled_suffix_survives_resolution(
            &root.path().join("a/missing/deeper"),
            root.path()
        ));
    }

    #[test]
    fn a_symlink_below_the_root_is_refused() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::create_dir_all(outside.path().join("code")).expect("outside tree");
        symlink(outside.path(), root.path().join("link")).expect("escape link");
        for spelled in ["link", "link/code", "link/code/new-file"] {
            assert!(
                !spelled_suffix_survives_resolution(&root.path().join(spelled), root.path()),
                "{spelled} escapes through the link"
            );
        }
        // A link that stays inside the root still changes the spelled suffix.
        std::fs::create_dir_all(root.path().join("real")).expect("real dir");
        symlink(root.path().join("real"), root.path().join("alias")).expect("alias");
        assert!(!spelled_suffix_survives_resolution(
            &root.path().join("alias/x"),
            root.path()
        ));
    }

    #[test]
    fn a_dangling_symlink_target_is_refused() {
        let root = tempfile::tempdir().expect("root");
        symlink(root.path().join("nowhere"), root.path().join("dangling")).expect("dangling");
        assert!(!spelled_suffix_survives_resolution(
            &root.path().join("dangling"),
            root.path()
        ));
    }

    #[test]
    fn a_symlinked_root_resolves_on_both_sides() {
        let real = tempfile::tempdir().expect("real root");
        let holder = tempfile::tempdir().expect("holder");
        let root = holder.path().join("root-link");
        symlink(real.path(), &root).expect("root link");
        std::fs::create_dir_all(real.path().join("x")).expect("x");
        assert!(spelled_suffix_survives_resolution(&root.join("x"), &root));
    }

    #[test]
    fn a_target_outside_the_root_is_refused() {
        let root = tempfile::tempdir().expect("root");
        let other = tempfile::tempdir().expect("other");
        assert!(!spelled_suffix_survives_resolution(
            other.path(),
            root.path()
        ));
        assert!(!spelled_suffix_survives_resolution(
            Path::new("relative/x"),
            root.path()
        ));
    }
}
