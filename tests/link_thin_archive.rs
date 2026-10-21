#![cfg(target_os = "linux")]

mod common;

use std::{fs, process::Command};

use common::map::archive_section;
use common::toolchain::{
    assemble_object, cargo_linker, create_archive, create_thin_archive, read_output_bytes,
    run_executable,
};
use predicates::str::contains;
use tempfile::{TempDir, tempdir};

/// Seen from the archive, the second path takes 29 bytes: where GNU ld's map
/// starts wrapping. The third name is too long for an ar header.
const MEMBERS: [&str; 4] = [
    "obj/foo.o",
    "obj/twenty_nine_cols.o",
    "obj/nested/a_member_name_longer_than_sixteen.o",
    "obj/unused.o",
];

/// Lay out objects under `obj/` and a thin archive at `lib/libthin.a`, as a
/// build tree would. `_start` exits with `foo() + bar() + baz()`, which is 37.
fn build_tree() -> TempDir {
    let temp = tempdir().unwrap();
    fs::create_dir_all(temp.path().join("obj/nested")).unwrap();
    fs::create_dir(temp.path().join("lib")).unwrap();
    assemble_object(
        &temp,
        "obj/start",
        r#"
.globl _start
.text
_start:
    call foo
    mov %eax, %ebx
    call bar
    add %eax, %ebx
    call baz
    lea (%rax,%rbx), %edi
    mov $60, %eax
    syscall
"#,
    );
    assemble_object(
        &temp,
        "obj/foo",
        ".globl foo\n.text\nfoo:\n mov $30, %eax\n ret\n",
    );
    assemble_object(
        &temp,
        "obj/twenty_nine_cols",
        ".globl bar\n.text\nbar:\n mov $5, %eax\n ret\n",
    );
    assemble_object(
        &temp,
        "obj/nested/a_member_name_longer_than_sixteen",
        ".globl baz\n.text\nbaz:\n mov $2, %eax\n ret\n",
    );
    assemble_object(&temp, "obj/unused", ".globl unused\n.text\nunused:\n ret\n");
    create_thin_archive(&temp, "lib/libthin.a", &MEMBERS);
    temp
}

/// Run my_linker in the tree, so the thin archive's relative paths matter.
fn link_in(temp: &TempDir, args: &[&str]) -> assert_cmd::assert::Assert {
    cargo_linker().current_dir(temp.path()).args(args).assert()
}

fn gnu_ld_in(temp: &TempDir, args: &[&str]) -> std::process::Output {
    Command::new("ld")
        .current_dir(temp.path())
        .arg("-static")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn thin_archive_links_like_a_regular_archive() {
    let temp = build_tree();
    let members = MEMBERS.map(|member| temp.path().join(member));
    let members = members.each_ref().map(|member| member.as_path());
    let regular = create_archive(&temp, "libregular", &members);

    link_in(&temp, &["-o", "thin", "obj/start.o", "lib/libthin.a"]).success();
    link_in(
        &temp,
        &["-o", "regular", "obj/start.o", regular.to_str().unwrap()],
    )
    .success();

    // Archive names never reach the output, so where member bytes come from
    // must not change a single byte.
    assert_eq!(
        read_output_bytes(&temp.path().join("thin")),
        read_output_bytes(&temp.path().join("regular"))
    );
    run_executable(&temp.path().join("thin")).code(37);
}

#[test]
fn thin_archive_map_matches_gnu_ld() {
    let temp = build_tree();
    let args = ["obj/start.o", "lib/libthin.a"];

    link_in(
        &temp,
        &[&["-Map", "ours.map", "-o", "ours"][..], &args].concat(),
    )
    .success();
    let gnu = gnu_ld_in(
        &temp,
        &[&["-Map", "gnu.map", "-o", "gnu"][..], &args].concat(),
    );
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    let ours = archive_section(&fs::read_to_string(temp.path().join("ours.map")).unwrap());
    let gnu = archive_section(&fs::read_to_string(temp.path().join("gnu.map")).unwrap());
    assert_eq!(ours, gnu);
    // GNU ld names a thin member by its file path, joined to the archive's directory.
    assert!(ours.contains("lib/../obj/foo.o "), "{ours}");
    assert!(ours.contains("lib/../obj/twenty_nine_cols.o\n"), "{ours}");
}

#[test]
fn missing_thin_member_file_fails_only_when_pulled() {
    let temp = build_tree();
    let args = ["-o", "out", "obj/start.o", "lib/libthin.a"];

    fs::remove_file(temp.path().join("obj/unused.o")).unwrap();
    link_in(&temp, &args).success();
    assert!(gnu_ld_in(&temp, &args).status.success());

    fs::remove_file(temp.path().join("obj/foo.o")).unwrap();
    let message = "lib/libthin.a(lib/../obj/foo.o): error opening thin archive member: \
                   No such file or directory";
    link_in(&temp, &args).failure().stderr(contains(message));
    let gnu = gnu_ld_in(&temp, &args);
    assert!(!gnu.status.success());
    assert!(String::from_utf8_lossy(&gnu.stderr).contains(message));
}
