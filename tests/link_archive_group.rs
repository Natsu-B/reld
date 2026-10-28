//! Check archive cycles, group diagnostics, and extraction order against GNU ld.

#![cfg(target_os = "linux")]

mod common;

use std::{fs, process::Command};

use common::map::archive_section;
use common::toolchain::{
    assemble_object, cargo_linker, compile_c_object, create_archive, glibc_static_toolchain,
    run_executable,
};
use predicates::{prelude::*, str::contains};
use tempfile::{TempDir, tempdir};

fn cycle_fixture() -> TempDir {
    let temp = tempdir().unwrap();
    assemble_object(
        &temp,
        "root",
        r#"
.globl _start
.text
_start:
    call a
    mov %eax, %edi
    mov $60, %eax
    syscall
"#,
    );
    let a = assemble_object(&temp, "a", ".globl a\n.text\na: jmp b\n");
    let a2 = assemble_object(&temp, "a2", ".globl a2\n.text\na2: mov $37, %eax\n ret\n");
    let b = assemble_object(&temp, "b", ".globl b\n.text\nb: jmp a2\n");
    create_archive(&temp, "liba", &[&a, &a2]);
    create_archive(&temp, "libb", &[&b]);
    temp
}

#[test]
fn a_group_resolves_an_archive_cycle_and_matches_gnu_ld_map_order() {
    let temp = cycle_fixture();
    cargo_linker()
        .current_dir(temp.path())
        .args(["-o", "out", "root.o", "liba.a", "libb.a"])
        .assert()
        .failure()
        .stderr(contains("undefined symbol: a2 in file: libb.a(b.o)"));

    for (start, end) in [("--start-group", "--end-group"), ("-(", "-)")] {
        let inputs = ["root.o", start, "liba.a", "libb.a", end];
        cargo_linker()
            .current_dir(temp.path())
            .args(["-o", "ours", "-Map", "ours.map"])
            .args(inputs)
            .assert()
            .success()
            .stderr("");
        let gnu = Command::new("ld")
            .current_dir(temp.path())
            .args(["-static", "-o", "gnu", "-Map", "gnu.map"])
            .args(inputs)
            .output()
            .unwrap();
        assert!(
            gnu.status.success(),
            "{}",
            String::from_utf8_lossy(&gnu.stderr)
        );
        assert_eq!(
            archive_section(&fs::read_to_string(temp.path().join("ours.map")).unwrap()),
            archive_section(&fs::read_to_string(temp.path().join("gnu.map")).unwrap()),
        );
        run_executable(&temp.path().join("ours")).code(37);
        run_executable(&temp.path().join("gnu")).code(37);
    }
}

#[test]
fn invalid_group_boundaries_fail_before_opening_inputs() {
    for (options, message) in [
        (vec!["--end-group"], "group ended before it began"),
        (
            vec!["--start-group", "--start-group"],
            "nested --start-group is not supported",
        ),
    ] {
        cargo_linker()
            .args(["-o", "out", "missing.o"])
            .args(options)
            .assert()
            .code(2)
            .stderr(contains(format!("error: {message}")))
            .stderr(contains("failed to open").not());
    }
}

#[test]
fn a_missing_end_group_warns_and_closes_after_the_last_input() {
    let temp = cycle_fixture();
    cargo_linker()
        .current_dir(temp.path())
        .args(["-o", "out", "root.o", "--start-group", "liba.a", "libb.a"])
        .assert()
        .success()
        .stderr(contains(
            "missing --end-group; added as last command line option",
        ));
    run_executable(&temp.path().join("out")).code(37);
}

#[test]
fn glibc_hello_with_gcc_archive_groups_matches_gnu_ld_map_order() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "hello",
        "#include <stdio.h>\nint main(void) { puts(\"hello, glibc\"); return 0; }\n",
    );
    let inputs = toolchain.grouped_link_inputs(&[main.as_path()]);
    cargo_linker()
        .current_dir(temp.path())
        .args(["-o", "ours", "-Map", "ours.map"])
        .args(&inputs)
        .assert()
        .success()
        .stdout("")
        .stderr("");
    let gnu = Command::new("ld")
        .current_dir(temp.path())
        .args(["-static", "-o", "gnu", "-Map", "gnu.map"])
        .args(&inputs)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );
    assert_eq!(
        archive_section(&fs::read_to_string(temp.path().join("ours.map")).unwrap()),
        archive_section(&fs::read_to_string(temp.path().join("gnu.map")).unwrap()),
    );
    for output in ["ours", "gnu"] {
        run_executable(&temp.path().join(output))
            .success()
            .stdout("hello, glibc\n");
    }
}
