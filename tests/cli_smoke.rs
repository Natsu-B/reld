use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

#[test]
fn help_works() {
    let mut command = Command::cargo_bin("reld").unwrap();
    command.env("NO_COLOR", "1");
    command.env("RAYON_NUM_THREADS", "1");
    command.arg("--help").assert().success();
}

#[test]
fn missing_input_file_fails() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("out");

    let mut command = Command::cargo_bin("reld").unwrap();
    command.env("NO_COLOR", "1");
    command.env("RAYON_NUM_THREADS", "1");

    command
        .arg("--debug")
        .arg("1")
        .arg("-o")
        .arg(&output)
        .arg("no_such_file.o")
        .assert()
        .failure()
        .stderr(contains("failed to open file"));
}
