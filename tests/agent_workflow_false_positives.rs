//! Commands coding agents run in ordinary work that dcg used to refuse, and
//! the dangerous neighbours of every relaxation, which must stay refused.
//!
//! Each case drives the real hook binary in a sandbox: an isolated `HOME`
//! under Cargo's per-target temp directory (so no home path is also a `/tmp`
//! path), a project directory as the working directory, and an empty user
//! config unless a test supplies one. Commands spell the sandbox paths
//! absolutely, the way the reported commands did. Temp-root cases use a
//! separate directory created under `/tmp`.
#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Sandbox {
    _root: tempfile::TempDir,
    _tmp: tempfile::TempDir,
    /// The isolated home directory, spelled for commands.
    home: String,
    /// A scratch directory under `/tmp`, outside the home directory.
    tmp: String,
    /// A directory that is neither under home nor under a temp root.
    outside: String,
    project: PathBuf,
    xdg_config: PathBuf,
}

const HOME_FILES: &[&str] = &[
    ".zshrc",
    ".ssh/id_ed25519",
    "reports/existing.md",
    "reports/data/old-name.tsv",
    "reports/data/taken.tsv",
    "package.json",
    "build/out.txt",
    "code/app/package.json",
    "code/app/src/main.js",
    "code/app/node_modules/pkg/index.js",
    "code/app/.next/cache/page.html",
    "code/app/dist/app.js",
    "code/lib/package.json",
    "code/lib/build/.git/HEAD",
    "code/no-manifest/dist/app.js",
    "Library/Caches/com.example.updater/Updates/update.zip",
    ".cache/tool/proof/data.bin",
    ".claude/jobs/abc/tmp/log",
    ".dev-browser/tmp/shot.png",
];

fn write_file(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("fixture dir");
    std::fs::write(path, b"keep").expect("fixture file");
}

/// The opt-in packs the reported sessions ran with, so their container and
/// Cloudflare rules are live in every case.
const AGENT_PACKS: &str = r#"
[packs]
enabled = ["containers.docker", "cdn.cloudflare_workers"]
"#;

impl Sandbox {
    fn new() -> Self {
        Self::with_config("")
    }

    /// A sandbox whose user config enables [`AGENT_PACKS`] and adds
    /// `extra_toml`.
    fn with_config(extra_toml: &str) -> Self {
        let root_dir = tempfile::Builder::new()
            .prefix("dcg-agent-workflow-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("sandbox root");
        let root = std::fs::canonicalize(root_dir.path()).expect("canonical root");
        let home = root.join("home");
        let outside = root.join("outside");
        let project = root.join("project");
        let xdg_config = root.join("xdg_config");
        for file in HOME_FILES {
            write_file(&home.join(file));
        }
        std::fs::create_dir_all(home.join("reports/drafts")).expect("drafts dir");
        write_file(&outside.join("data.txt"));
        write_file(&project.join("src/a.ts"));
        std::fs::create_dir_all(project.join(".git")).expect("project repo");
        symlink(&outside, home.join("link-out")).expect("link out of home");
        symlink(home.join("code"), home.join("Library/Caches/link-code")).expect("cache link");
        symlink(home.join("code/app/src"), home.join("code/app/build")).expect("build link");
        symlink(&home, home.join(".claude/jobs/abc/tmp/link")).expect("job link");

        let tmp_dir = tempfile::Builder::new()
            .prefix("dcg-agent-workflow-")
            .tempdir_in("/tmp")
            .expect("temp scratch");
        let tmp = tmp_dir.path().to_path_buf();
        write_file(&tmp.join("prove/copy.json"));
        write_file(&tmp.join("scratch-root/state.db"));
        symlink(&home, tmp.join("link-home")).expect("temp link to home");

        let user_config_dir = xdg_config.join("dcg");
        std::fs::create_dir_all(&user_config_dir).expect("config dir");
        std::fs::write(
            user_config_dir.join("config.toml"),
            format!("{AGENT_PACKS}{extra_toml}"),
        )
        .expect("config");
        Self {
            _root: root_dir,
            _tmp: tmp_dir,
            home: home.to_string_lossy().into_owned(),
            tmp: tmp.to_string_lossy().into_owned(),
            outside: outside.to_string_lossy().into_owned(),
            project,
            xdg_config,
        }
    }

    /// The rule that denies `command`, or `None` when the hook allows it.
    fn denial(&self, command: &str) -> Option<String> {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("DCG_CONFIG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dcg");
        {
            let stdin = child.stdin.as_mut().expect("stdin");
            serde_json::to_writer(stdin, &input).expect("write hook input");
        }
        let output = child.wait_with_output().expect("wait for dcg");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return None;
        }
        let json: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("hook output is not JSON ({error}): {stdout}"));
        let hook = &json["hookSpecificOutput"];
        (hook["permissionDecision"] == "deny").then(|| {
            hook["ruleId"]
                .as_str()
                .unwrap_or("<no rule id>")
                .to_string()
        })
    }

    #[track_caller]
    fn assert_allows(&self, command: &str) {
        if let Some(rule) = self.denial(command) {
            panic!("expected an allow, {rule} denied:\n{command}");
        }
    }

    #[track_caller]
    fn assert_denies(&self, command: &str) {
        assert!(
            self.denial(command).is_some(),
            "expected a denial:\n{command}"
        );
    }
}

// ---------------------------------------------------------------- redirects

#[test]
fn a_variable_naming_a_new_file_in_an_existing_home_directory_is_creation() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    sandbox.assert_allows(&format!(
        "root={home}/reports/drafts\nout=\"$root/model.md\"\n\
         pi --model some/model -p @prompt.md >\"$out\" 2>\"$root/model.log\""
    ));
}

#[test]
fn a_variable_redirect_to_an_existing_escaping_or_unset_target_stays_denied() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    for command in [
        format!("root={home}/reports\nout=\"$root/existing.md\"\npi -p x >\"$out\""),
        format!("root={home}\npi -p x >\"$root/.zshrc\""),
        format!("root={home}/reports/drafts\npi -p x >\"$root/../new.md\""),
        format!("root={home}/link-out\npi -p x >\"$root/new.md\""),
        format!("root={home}/reports/drafts/\npi -p x >\"$root.git/config\""),
        "pi -p x >\"$UNSET_ROOT/model.md\"".to_string(),
        "root=~\npi -p x >\"$root/.zshrc\"".to_string(),
        "pi -p x >\"$HOME/.zshrc\"".to_string(),
    ] {
        sandbox.assert_denies(&command);
    }
}

#[test]
fn a_file_in_a_directory_the_same_command_creates_first_is_creation() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    sandbox.assert_allows(&format!(
        "mkdir {home}/reports/run-1 && node -e 'console.log(1)' > {home}/reports/run-1/new.log"
    ));
    sandbox.assert_allows(&format!(
        "mkdir -p {home}/reports/run-2/evidence && node -e 'console.log(1)' \
         > {home}/reports/run-2/evidence/baseline.txt"
    ));
}

#[test]
fn created_directory_credit_needs_a_leading_literal_mkdir_inside_home() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    for command in [
        format!("mkdir {home}/reports/run-3 && echo x > {home}/.zshrc"),
        format!("mkdir {home}/reports/run-3 && echo x > {home}/reports/other/f.log"),
        format!("mkdir -p {home}/reports/run-3 && echo x > {home}/reports/run-3/../../.zshrc"),
        format!("mkdir {home}/link-out/run && echo x > {home}/link-out/run/f.log"),
        format!("mkdir $D && echo x > {home}/reports/run-4/f.log"),
        format!("mkdir {home}/reports/run-5; echo x > {home}/.zshrc"),
        format!("mkdir {home}/reports/run-6 && echo x > {home}/reports/run-6/.git/config"),
        format!("echo x > {home}/reports/run-7/f.log && mkdir {home}/reports/run-7"),
    ] {
        sandbox.assert_denies(&command);
    }
}

#[test]
fn a_redirect_inside_a_subshell_group_is_judged_by_its_target() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    sandbox.assert_allows(&format!(
        "for p in {home}/reports/a.json {home}/reports/a.md; do test ! -e \"$p\" || exit 1; done; \
         (umask 077; set -o noclobber; : > {home}/reports/a.json && : > {home}/reports/a.md)"
    ));
    sandbox.assert_denies(&format!("(umask 077; : > {home}/.zshrc)"));
    sandbox.assert_denies(&format!("(: > {home}/reports/existing.md)"));
}

const EXEMPT_AGENT_SCRATCH: &str = r#"
[rules."core.filesystem:redirect-truncate-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**", "~/.dev-browser/tmp/**"]
"#;

#[test]
fn an_exempt_target_glob_covers_its_tree_but_not_a_symlink_out_of_it() {
    let sandbox = Sandbox::with_config(EXEMPT_AGENT_SCRATCH);
    sandbox.assert_allows("printf b > ~/.dev-browser/tmp/shot.png");
    sandbox.assert_allows("printf b > ~/.claude/jobs/abc/tmp/log");
    sandbox.assert_denies("printf b > ~/.claude/jobs/abc/tmp/link/.zshrc");
    sandbox.assert_denies("printf b > ~/.dev-browser/tmp/../../.zshrc");
    // Without the config the same existing file stays protected.
    Sandbox::new().assert_denies("printf b > ~/.dev-browser/tmp/shot.png");
}

// ------------------------------------------------------------------ reclaim

#[test]
fn regenerable_build_output_next_to_a_manifest_can_be_reclaimed() {
    let sandbox = Sandbox::new();
    let app = format!("{}/code/app", sandbox.home);
    sandbox.assert_allows(&format!("rm -rf {app}/node_modules"));
    sandbox.assert_allows(&format!("rm -rf {app}/.next {app}/dist"));
    sandbox.assert_allows(&format!("find {app}/.next -mindepth 1 -delete"));
    sandbox.assert_allows(&format!("find {app}/node_modules -mindepth 1 -delete"));
    sandbox.assert_allows("rm -rf ~/code/app/node_modules");
}

#[test]
fn reclaim_refuses_anything_but_a_literal_build_output_directory() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    for command in [
        format!("rm -rf {home}/code/app"),
        format!("rm -rf {home}/code/app/src"),
        format!("rm -rf {home}/code/app/build"),
        format!("rm -rf {home}/code/app/build/"),
        format!("rm -rf {home}/code/no-manifest/dist"),
        format!("rm -rf {home}/code/lib/build"),
        format!("rm -rf {home}/build"),
        format!("rm -rf {home}/code/*/node_modules"),
        format!("rm -rf {home}/code/app/../app/node_modules"),
        format!("rm -rf {home}/code/app/node_modules {home}/code/app/src"),
        "rm -rf $HOME/code/app/node_modules".to_string(),
        "rm -rf \"$HOME/code/app/node_modules\"".to_string(),
        "rm -rf ${HOME}/code/app/node_modules".to_string(),
        "rm -rf $UNSET_DIR/node_modules".to_string(),
        "rm -rf ~".to_string(),
        "rm -rf ~/".to_string(),
        "rm -rf /".to_string(),
        "rm -rf /usr/local/build".to_string(),
        format!("find {home}/code/app -mindepth 1 -delete"),
        format!("find -L {home}/code/app/node_modules -delete"),
        format!("find {home}/code/app/node_modules -name '*.js' -delete"),
        format!("find {home}/code/app/node_modules -delete; rm -rf ~"),
    ] {
        sandbox.assert_denies(&command);
    }
}

#[test]
fn updater_caches_below_library_caches_can_be_reclaimed() {
    let sandbox = Sandbox::new();
    let caches = format!("{}/Library/Caches", sandbox.home);
    sandbox.assert_allows(&format!("rm -rf {caches}/com.example.updater/Updates"));
    sandbox.assert_allows(&format!(
        "find {caches}/com.example.updater -mindepth 1 -delete"
    ));
}

#[test]
fn reclaim_refuses_the_cache_root_its_parents_links_and_other_caches() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    for command in [
        format!("rm -rf {home}/Library/Caches"),
        format!("rm -rf {home}/Library/Caches/"),
        format!("rm -rf {home}/Library"),
        format!("rm -rf {home}/Library/Caches/link-code/app"),
        format!("rm -rf {home}/Library/Caches/link-code/"),
        format!("rm -rf {home}/Library/Caches/*"),
        format!("rm -rf {home}/Library/Caches/com.example.updater/../../../code"),
        format!("find {home}/Library/Caches -mindepth 1 -delete"),
        // `~/.cache` is outside the policy and keeps the deny.
        format!("rm -rf {home}/.cache/tool/proof"),
        format!("find {home}/.cache/tool/proof -delete"),
        "rm -r \"$HOME/Library/Caches/com.example.updater/Updates\"".to_string(),
        "rm -rf /Library/Caches/com.example.updater".to_string(),
        "rm -rf /System/Library/Caches".to_string(),
    ] {
        sandbox.assert_denies(&command);
    }
}

#[test]
fn temp_scratch_can_be_reclaimed_but_not_through_a_link_into_home() {
    let sandbox = Sandbox::new();
    let tmp = &sandbox.tmp;
    sandbox.assert_allows(&format!("rm -r {tmp}/prove"));
    sandbox.assert_allows(&format!("find {tmp}/prove -delete"));
    sandbox.assert_allows(&format!(
        "S={tmp}\nrm -rf \"$S/scratch-root\"; bun src/cli.ts probe --root \"$S/scratch-root\""
    ));
    for command in [
        format!("rm -rf {tmp}/link-home/"),
        format!("rm -rf {tmp}/link-home/code"),
        format!("find {tmp}/link-home/ -delete"),
        format!("rm -rf {tmp}/link-home/code/app/node_modules/../../.."),
        "rm -rf /tmp".to_string(),
        "rm -rf /private/tmp".to_string(),
        "rm -rf /tmp/..".to_string(),
    ] {
        sandbox.assert_denies(&command);
    }
}

/// `find -delete` with the `/private/tmp` spelling only names a temp tree
/// where `/tmp` is a link to `/private/tmp`.
#[cfg(target_os = "macos")]
#[test]
fn find_delete_under_the_private_tmp_spelling_is_temp_scratch() {
    let sandbox = Sandbox::new();
    let tmp = &sandbox.tmp;
    sandbox.assert_allows(&format!("find /private{tmp}/prove -delete"));
    sandbox.assert_allows(&format!("rm -rf /private{tmp}/prove"));
    sandbox.assert_denies(&format!("find /private{tmp}/link-home/ -delete"));
}

/// The macOS per-user temp directory (`TMPDIR`, `/var/folders/<a>/<b>/T`)
/// holds `mktemp -d` output; deleting below it is temp cleanup.
#[cfg(target_os = "macos")]
#[test]
fn the_macos_per_user_temp_directory_is_temp_scratch() {
    let sandbox = Sandbox::new();
    let tmpdir = std::env::temp_dir();
    let scratch = tempfile::Builder::new()
        .prefix("tmp.")
        .tempdir_in(&tmpdir)
        .expect("per-user temp scratch");
    write_file(&scratch.path().join("download/part.bin"));
    symlink(&sandbox.home, scratch.path().join("link-home")).expect("link to home");
    let scratch = scratch.path().to_string_lossy();
    let root = tmpdir.to_string_lossy();
    let root = root.trim_end_matches('/');
    sandbox.assert_allows(&format!("rm -r {scratch}/download"));
    sandbox.assert_allows(&format!("rm -r {scratch}"));
    sandbox.assert_allows(&format!("find {scratch}/download -delete"));
    sandbox.assert_denies(&format!("rm -r {root}"));
    sandbox.assert_denies(&format!("rm -r {root}/"));
    sandbox.assert_denies(&format!("rm -r {scratch}/link-home/"));
    sandbox.assert_denies(&format!("rm -r {scratch}/link-home/code"));
    sandbox.assert_denies(&format!("rm -r {root}/../C"));
}

#[test]
fn deletes_the_policy_does_not_cover_stay_denied() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    let outside = &sandbox.outside;
    for command in [
        // Dynamic operands, even when they resolve to temp or cache paths.
        "T=$(mktemp -d /tmp/review.XXXXXX)\nfor f in .review-*; do mv \"$f\" \"$T/\"; done"
            .to_string(),
        format!("D={home}/reports/data; mv $D/old-name.tsv $D/new-name.tsv"),
        // Relative and interpreter deletions are outside the policy.
        "mkdir x && rm -rf x".to_string(),
        format!("python3 -c \"import shutil; shutil.rmtree('{home}/code/app/node_modules')\""),
        // A directory that is neither temp, cache nor build output.
        format!("rm -rf {outside}"),
        format!("find {outside} -delete"),
    ] {
        sandbox.assert_denies(&command);
    }
}

// ------------------------------------------------------------------ renames

#[test]
fn renaming_a_file_within_its_home_directory_is_not_a_relocation() {
    let sandbox = Sandbox::new();
    let data = format!("{}/reports/data", sandbox.home);
    sandbox.assert_allows(&format!("mv {data}/old-name.tsv {data}/new-name.tsv"));
    sandbox.assert_allows(&format!("mv -n {data}/old-name.tsv {data}/new-name.tsv"));
}

#[test]
fn a_rename_that_overwrites_leaves_the_directory_or_touches_secrets_stays_denied() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    let data = format!("{home}/reports/data");
    for command in [
        format!("mv {data}/old-name.tsv {data}/taken.tsv"),
        format!("mv {data}/old-name.tsv {home}/reports/new-name.tsv"),
        format!("mv {data}/old-name.tsv {}/moved.tsv", sandbox.tmp),
        format!("mv {home}/.zshrc {home}/.zshrc.bak"),
        format!("mv {home}/.ssh/id_ed25519 {home}/.ssh/id_old"),
        format!("mv {home}/link-out/data.txt {home}/link-out/renamed.txt"),
        format!("mv -f {data}/old-name.tsv {data}/new-name.tsv"),
        format!("mv {data}/old-name.tsv {data}/taken.tsv {data}/new-name.tsv"),
        format!("mv {data}/missing.tsv {data}/new-name.tsv; rm -rf ~"),
        format!("mv {data}/../data/old-name.tsv {data}/new-name.tsv"),
        "mv $HOME/reports/data/old-name.tsv $HOME/reports/data/new-name.tsv".to_string(),
    ] {
        sandbox.assert_denies(&command);
    }
}

// ----------------------------------------------------------------- heredocs

#[test]
fn interpreter_bodies_with_shell_like_text_are_program_data() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    for command in [
        "node --input-type=module <<'EOF'\nconst skills = [];\n\
         console.log(skills.filter(s=>!s.disableModelInvocation).length);\nEOF"
            .to_string(),
        format!(
            "python3 - <<'EOF'\nfrom pathlib import Path\n\
             doc = \"\"\"## Run\n\nRun `bash -c \"$(cat scripts/run.sh)\"` to start.\n\"\"\"\n\
             Path(\"{home}/reports/notes.md\").write_text(doc)\nEOF"
        ),
    ] {
        sandbox.assert_allows(&command);
    }
}

#[test]
fn executing_heredoc_bodies_stay_denied() {
    let sandbox = Sandbox::new();
    for command in [
        "bash <<'EOF'\nrm -rf ~/code\nEOF",
        "bash <<'EOF'\nbash -c \"$(cat scripts/run.sh)\"\nEOF",
        "cat <<'EOF' | sh\nrm -rf ~/code\nEOF",
        "python3 - <<'EOF'\nimport shutil\nshutil.rmtree('/home/user')\nEOF",
        "node --input-type=module <<'EOF'\nrequire('fs').rmSync('/home/user', {recursive: true});\nEOF",
    ] {
        sandbox.assert_denies(command);
    }
}

// ----------------------------------------------------------------- wrangler

fn template_literal_lines(count: usize) -> String {
    (0..count)
        .map(|index| format!("const x{index} = `${{a}} ${{b}}`;"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_wrangler_rule_needs_a_command_that_can_run_wrangler() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    let big_python = format!(
        "cd /tmp && python3 - <<'EOF'\ns = \"\"\"\n{}\n\"\"\"\nprint(len(s))\nEOF",
        template_literal_lines(400)
    );
    let browser_lines = (0..120)
        .map(|index| {
            format!(
                "  await page.goto(`http://localhost:${{port}}/{index}`); \
                 // dev-browser --timeout {index}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let patch_script = format!(
        "python3 - <<'EOF'\nfrom pathlib import Path\np = Path(\"test/bundles/local.mjs\")\n\
         s = p.read_text()\nnew = \"\"\"\n{browser_lines}\n\"\"\"\n\
         s = s.replace(\"// old\", new)\np.write_text(s)\nEOF"
    );
    for command in [
        format!(
            "T={home}/reports/data/taken.tsv\nbun -e 'const t = require(\"fs\")\
             .readFileSync(process.argv[1], \"utf8\"); console.log(t.split(/\\n/).length);' $T"
        ),
        big_python,
        "ls a/probe.mjs ../x/probe.mjs 2>&1 | head -2; \
         node $(ls a/probe.mjs ../x/probe.mjs 2>/dev/null | head -1) $PWD; echo \"exit $?\""
            .to_string(),
        patch_script,
    ] {
        sandbox.assert_allows(&command);
    }
}

#[test]
fn commands_that_can_run_wrangler_keep_the_wrangler_rule() {
    let sandbox = Sandbox::new();
    for command in [
        "npx wrangler delete my-worker",
        "W=wrangler; pnpm exec $W delete my-worker",
        "pnpm exec wrangler delete my-worker",
        "node $(command -v wrangler) delete my-worker",
        "bash <<'EOF'\nnpx wrangler delete my-worker\nEOF",
    ] {
        sandbox.assert_denies(command);
    }
}

// ------------------------------------------- reported commands already fixed

/// Commands from earlier reports that dcg already allows. They guard the
/// current verdicts against regressions.
#[test]
fn reported_everyday_commands_stay_allowed() {
    let sandbox = Sandbox::new();
    let home = &sandbox.home;
    let tmp = &sandbox.tmp;
    let numbered_python = (0..20)
        .map(|index| format!("print({index})"))
        .collect::<Vec<_>>()
        .join("\n");
    for command in [
        format!("node build.mjs > {tmp}/prove/copy.json 2>&1"),
        format!("S={tmp}\npnpm exec tsx scripts/probe.mts --size M > $S/stdout.log"),
        format!("A={home}/code/app; git -C $A status --short"),
        "W=/tmp/w; f=form; git -C $W show HEAD:x/$f.ts".to_string(),
        "git -c $X show HEAD:x/$f.ts".to_string(),
        format!(
            "S={tmp}\npython3 - <<'PY'\nprint(\"x\")\nPY\n./deploy.sh validate > $S/validate.log 2>&1"
        ),
        "LOG=/private/tmp/x.log; echo hi > $LOG".to_string(),
        format!("rm -rf {tmp}/scratch-root"),
        format!(
            "cat > {tmp}/note.md <<'EOF'\nTo reclaim, the owner may run rm -rf ~/code/x after review.\nEOF"
        ),
        "for f in $(git diff --name-only HEAD~1); do echo \"$f\"; done".to_string(),
        format!(
            "python3 - <<'EOF'\nfrom pathlib import Path\ntext = \"\"\"# Handover\n\n\
             Do not TRUNCATE TABLE contacts; keep every contact row.\n\"\"\"\n\
             Path(\"{tmp}/HANDOVER.md\").write_text(text)\nEOF"
        ),
        "curl -s -o /dev/null http://localhost:3000/ && dev-browser --headless <<'EOF'\n\
         const wait = (ms) => new Promise((r) => setTimeout(r, ms));\nawait wait(10);\nEOF"
            .to_string(),
        "uv run python - <<'EOF'\nimport json, sys\nprint(json.dumps({\"a\": 1}), file=sys.stderr)\nEOF"
            .to_string(),
        "docker rm app-deps".to_string(),
        "docker rm app-deps; docker ps --format '{{.Names}}'".to_string(),
        format!("S={tmp} && cat > $S/probe.sh <<'EOF'\n: > \"$work/empty-gitconfig\"\nEOF"),
        "dev-browser --headless <<'EOF'\nconst page = await browser.getPage(\"x\");\n\
         const over = await page.evaluate(() => document.body.scrollHeight > document.body.clientHeight);\n\
         console.log(over);\nEOF"
            .to_string(),
        format!("SP={tmp}; echo hi > \"$SP/a.txt\""),
        "python3 - <<'EOF'\njs = \"const s = `hello ${name}`;\"\nprint(js)\nEOF".to_string(),
        format!("SCRATCH={tmp}; cat > \"$SCRATCH/helper.py\" <<'EOF'\nimport sys\nprint(sys.argv)\nEOF"),
        "python3 - <<'EOF'\nimport ast\nprint(\"ok\")\nEOF\nnode - <<'EOF'\n\
         console.log([1, 2].filter(n => n > 0).length > 0);\nEOF"
            .to_string(),
        "dev-browser --headless <<'JS'\nconst links = [];\n\
         console.log(links.filter(a => !document.getElementById(a.id)).length);\nJS"
            .to_string(),
        "dev-browser --headless <<'EOF'\nconst page = await browser.getPage('x'); page.on('console', m=>{});\nEOF"
            .to_string(),
        "grep -rl TODO src | sort | awk '{print $1}'".to_string(),
        "git show :1:src/a.ts > src/a.ts".to_string(),
        "docker rmi app-server:feature app-web:feature".to_string(),
        "umask 077; while ! mkdir models/.lock-example; do sleep 30; done".to_string(),
        "for file in fetch-check-01.js fetch-check-02.js; do name=${file##*/fetch-}; echo \"$name\"; done"
            .to_string(),
        "umask 077; sleep 600".to_string(),
        "until [[ $(date -u +%H%M) == 0031 ]]; do sleep 20; done; date -u +%T".to_string(),
        "bd comments add task-1 \"Handoff: after review run pnpm exec wrangler deploy --env $ENV.\""
            .to_string(),
        "pnpm exec wrangler d1 execute DB --local --command \"SELECT count(*) FROM $T\"".to_string(),
        "sed -n '1427,1532p' packages/kernel/src/solver.ts".to_string(),
        "git status --short && git diff --stat".to_string(),
        "git ls-files .github/workflows | sed -n '1,20p' | sort | awk '{print $1}'".to_string(),
        format!("python3 - <<'EOF'\n{numbered_python}\nEOF"),
    ] {
        sandbox.assert_allows(&command);
    }
}

/// Neighbours of the reported commands that discard work or force-delete;
/// they keep their deny.
#[test]
fn reported_commands_dangerous_neighbours_stay_denied() {
    let sandbox = Sandbox::new();
    for command in [
        "git branch $f",
        "git checkout -- docs/contracts/fixtures.json",
        "git checkout --theirs -- src/a.ts",
        "docker rm -f app-deps",
        "docker rm --force app-deps",
        "docker rmi -f app-server:latest",
        "git reset --hard",
        "git clean -fdx",
        "git push --force origin main",
    ] {
        sandbox.assert_denies(command);
    }
}
