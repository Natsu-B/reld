#![cfg(target_os = "linux")]

mod common;

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, link_executable_input, parse_elf64, read_output_bytes,
};
use elf::ElfFileType;
use predicates::str::contains;
use tempfile::tempdir;

#[test]
fn fails_on_undefined_symbol() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "undefined",
        r#"
.global _start
.text
_start:
    call foo
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );
    let output = temp.path().join("out");

    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .failure()
        .stderr(contains(format!(
            "undefined symbol: foo in file: {}",
            input.display()
        )));
}

#[test]
fn fails_on_duplicate_strong_symbol() {
    let temp = tempdir().unwrap();
    let first = assemble_object(
        &temp,
        "a",
        r#"
.global _start
.global foo
.text
_start:
    call foo
    mov $60, %rax
    xor %rdi, %rdi
    syscall
foo:
    ret
"#,
    );
    let second = assemble_object(
        &temp,
        "b",
        r#"
.global foo
.text
foo:
    ret
"#,
    );
    let output = temp.path().join("duplicate_out");

    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .arg(&first)
        .arg(&second)
        .assert()
        .failure()
        .stderr(contains(format!(
            "multiple definition of symbol: foo in files: {} and {}",
            second.display(),
            first.display()
        )));
}

#[test]
fn rejects_et_exec_input() {
    let temp = tempdir().unwrap();
    let object = assemble_object(
        &temp,
        "exec_input",
        r#"
.global _start
.text
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );
    let exec_input = link_executable_input(&temp, "exec_input.bin", &[object.as_path()]);
    let exec_bytes = read_output_bytes(&exec_input);
    let exec_elf = parse_elf64(&exec_bytes);
    let output = temp.path().join("out");

    assert_eq!(exec_elf.elf_type(), ElfFileType::ET_EXEC);

    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .arg(&exec_input)
        .assert()
        .failure()
        .stderr(contains("unsupported file type"));
}
