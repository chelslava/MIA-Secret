use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use uuid::Uuid;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mia-secret-cli-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("failed to create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_mia-secret")
}

fn run_cli(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin_path())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to run cli")
}

fn stdout_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn cli_config_init_validate_and_show_work() {
    let root = TestDir::new("config-flow");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let init = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "init", "--force"],
    );
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        stderr_text(&init)
    );
    assert!(
        stdout_text(&init).contains("Config initialized"),
        "unexpected init output: {}",
        stdout_text(&init)
    );

    let validate = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "validate"],
    );
    assert!(
        validate.status.success(),
        "validate failed: stderr={}",
        stderr_text(&validate)
    );
    assert!(
        stdout_text(&validate).contains("Config is valid"),
        "unexpected validate output: {}",
        stdout_text(&validate)
    );

    let show = run_cli(root.path(), &["--config", &config_arg, "config", "show"]);
    assert!(
        show.status.success(),
        "show failed: stderr={}",
        stderr_text(&show)
    );
    let show_text = stdout_text(&show);
    assert!(show_text.contains("[server]"), "show output: {show_text}");
    assert!(
        show_text.contains("host = \"127.0.0.1\""),
        "show output: {show_text}"
    );
}

#[test]
fn cli_config_init_without_force_fails_on_existing_file() {
    let root = TestDir::new("config-init-fail");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let first = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "init", "--force"],
    );
    assert!(first.status.success(), "first init failed");

    let second = run_cli(root.path(), &["--config", &config_arg, "config", "init"]);
    assert!(
        !second.status.success(),
        "second init should fail, stdout={}",
        stdout_text(&second)
    );
    assert!(
        stderr_text(&second).contains("config already exists"),
        "unexpected stderr: {}",
        stderr_text(&second)
    );
}

#[test]
fn cli_serve_rejects_non_loopback_host_override() {
    let root = TestDir::new("serve-host");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let output = run_cli(
        root.path(),
        &["--config", &config_arg, "serve", "--host", "0.0.0.0"],
    );
    assert!(
        !output.status.success(),
        "serve should fail for non-loopback host"
    );
    let err = stderr_text(&output);
    assert!(
        err.contains("loopback"),
        "expected loopback validation error, got: {err}"
    );
}

#[test]
fn cli_init_creates_data_layout() {
    let root = TestDir::new("init-layout");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let config_init = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "init", "--force"],
    );
    assert!(config_init.status.success(), "config init failed");

    let init = run_cli(root.path(), &["--config", &config_arg, "init"]);
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        stderr_text(&init)
    );
    assert!(
        root.path().join("data").exists(),
        "data directory must exist"
    );
    assert!(
        root.path().join("data").join("master.key").exists(),
        "master key must exist"
    );
    assert!(
        root.path().join("data").join("secrets.db").exists(),
        "database must exist"
    );
}
