#![cfg(target_os = "linux")]

mod common;

use std::{fs, path::Path, process::Command};

use common::map::archive_section;
use common::toolchain::{
    assemble_object, cargo_linker, cargo_linker_with_debug, compile_c_object, create_archive,
    glibc_static_toolchain, parse_elf64, read_output_bytes, run_executable,
};
use tempfile::{TempDir, tempdir};

fn reporting_fixture() -> TempDir {
    let temp = tempdir().unwrap();
    assemble_object(
        &temp,
        "root",
        r#"
.globl _start, datum, tlsvar
.type _start, @function
.text
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
    call helper
    mov datum@GOTPCREL(%rip), %rax
    mov tlsvar@GOTTPOFF(%rip), %rax
    .long tlsvar@TPOFF
    .quad tlsvar@TPOFF
    call indirect
    .quad indirect
    mov $datum, %rax
    .long datum
    .reloc ., R_X86_64_NONE
    .quad 0
.weak chosen
.type chosen, @function
chosen: ret
.weak optional
.type optional, @function
optional: ret
.weak absent
.data
.type datum, @object
.size datum, 8
datum: .quad 42
    .quad provided, hidden, marker, absent - 8
.section .tdata,"awT",@progbits
.p2align 3
.type tlsvar, @tls_object
.size tlsvar, 8
tlsvar: .quad 7
.section .tbss,"awT",@nobits
.p2align 4
.type tlszero, @tls_object
tlszero: .zero 8
.section .mystery,"a",@progbits
.byte 0x5a
"#,
    );
    assemble_object(
        &temp,
        "winner",
        r#"
.text
.globl chosen, indirect
.type chosen, @function
chosen: ret
.type indirect, @gnu_indirect_function
indirect: ret
"#,
    );
    let second = assemble_object(&temp, "second", ".text\n.globl second\nsecond: ret\n");
    let helper = assemble_object(
        &temp,
        "helper",
        ".text\n.globl helper\nhelper: call second\nret\n",
    );
    let unused = assemble_object(&temp, "unused", ".text\n.globl absent\nabsent: ret\n");
    create_archive(&temp, "lib", &[&second, &helper, &unused]);
    fs::write(
        temp.path().join("link.ld"),
        r#"
ENTRY(_start)
SECTIONS {
    /DISCARD/ : { *(.note.gnu.property) }
    . = 0x400000 + SIZEOF_HEADERS;
    marker = .;
    .rela.iplt : { *(.rela.iplt) }
    .text : { *(.text) }
    .iplt : { *(.iplt) }
    .rodata : { *(.rodata) }
    . = ALIGN(0x1000);
    .tdata : { *(.tdata) }
    .tbss : { *(.tbss) }
    .data : { *(.data) }
    .got : { _GLOBAL_OFFSET_TABLE_ = .; *(.got) }
    .bss : { *(.bss) }
    PROVIDE(provided = 0x1234);
    PROVIDE_HIDDEN(hidden = 0x4321);
}
"#,
    )
    .unwrap();
    temp
}

fn linker(temp: &TempDir) -> assert_cmd::Command {
    let mut command = cargo_linker_with_debug(0);
    // Relative input names make the complete expected text portable.
    command
        .current_dir(temp.path())
        .args(["-T", "link.ld", "-o", "out", "root.o", "winner.o", "lib.a"]);
    command
}

fn golden(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/report")
            .join(name),
    )
    .unwrap()
}

#[test]
fn each_trace_phase_matches_its_golden_text() {
    let temp = reporting_fixture();
    for phase in [
        "inputs",
        "archive",
        "symbols",
        "mapping",
        "got",
        "layout",
        "relocations",
    ] {
        let result = linker(&temp).args(["--trace", phase]).assert().success();
        assert_eq!(result.get_output().stdout, b"", "phase: {phase}");
        assert_eq!(
            String::from_utf8_lossy(&result.get_output().stderr),
            golden(&format!("{phase}.txt")),
            "phase: {phase}",
        );
    }
    run_executable(&temp.path().join("out"))
        .success()
        .stdout("");
}

#[test]
fn comma_separated_and_repeated_traces_follow_stage_order() {
    let temp = reporting_fixture();
    let result = linker(&temp)
        .args([
            "--trace",
            "relocations,got,layout",
            "--trace",
            "symbols,inputs,archive,mapping,inputs",
        ])
        .assert()
        .success();
    let expected = [
        "inputs",
        "archive",
        "mapping",
        "symbols",
        "got",
        "layout",
        "relocations",
    ]
    .map(|phase| golden(&format!("{phase}.txt")))
    .concat();
    assert_eq!(result.get_output().stderr, expected.as_bytes());
}

#[test]
fn relocation_filter_matches_exact_names_and_is_repeatable() {
    let temp = reporting_fixture();
    for names in [vec!["datum"], vec!["datum", "tlsvar"], vec!["dat"]] {
        let mut command = linker(&temp);
        command.args(["--trace", "relocations"]);
        for name in &names {
            command.args(["--trace-symbol", name]);
        }
        let result = command.assert().success();
        let expected = golden("relocations.txt")
            .lines()
            .filter(|line| {
                !line.starts_with("R_X86_64_")
                    || names.iter().any(|name| line.contains(&format!(" {name} ")))
            })
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        assert_eq!(result.get_output().stderr, expected.as_bytes());
    }
}

#[test]
fn link_maps_accept_gnu_option_spellings_and_match_golden_text() {
    let temp = reporting_fixture();
    for args in [
        vec!["-Map", "out.map"],
        vec!["-Map=out.map"],
        vec!["--map", "out.map"],
        vec!["--Map=out.map"],
    ] {
        linker(&temp)
            .args(args)
            .assert()
            .success()
            .stdout("")
            .stderr("");
        assert_eq!(
            fs::read_to_string(temp.path().join("out.map")).unwrap(),
            golden("map.txt")
        );
    }
}

#[test]
fn tracing_and_map_generation_preserve_output_bytes() {
    let temp = reporting_fixture();
    linker(&temp).assert().success().stdout("").stderr("");
    let plain = read_output_bytes(&temp.path().join("out"));
    let elf = parse_elf64(&plain);
    let tls = elf
        .program_headers()
        .find(|header| header.segment_type() == elf::ElfProgramHeaderType::PT_TLS)
        .unwrap();
    assert_eq!((tls.file_size(), tls.mem_size(), tls.align()), (8, 24, 16));
    linker(&temp)
        .args([
            "--trace",
            "inputs,archive,mapping,symbols,got,layout,relocations",
            "-Map=out.map",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(temp.path().join("out")).unwrap(), plain);
}

#[test]
fn unknown_trace_phase_lists_valid_names_before_opening_inputs() {
    cargo_linker()
        .args(["--trace", "bogus", "-o", "out", "missing.o"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "unknown trace phase 'bogus'; valid phases: inputs, archive, symbols, mapping, got, layout, relocations",
        ));
}

#[test]
fn glibc_hello_archive_map_matches_gnu_ld_exactly() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "hello",
        "#include <stdio.h>\nint main(void) { puts(\"hello, glibc\"); return 0; }\n",
    );
    let objects = [main.as_path()];
    let inputs = toolchain.link_inputs(&objects);
    let ours = temp.path().join("ours");
    let our_map = temp.path().join("ours.map");
    cargo_linker()
        .args([
            "-o".as_ref(),
            ours.as_os_str(),
            "-Map".as_ref(),
            our_map.as_os_str(),
        ])
        .args(&inputs)
        .assert()
        .success()
        .stdout("")
        .stderr("");
    let gnu = Command::new("ld")
        .arg("-static")
        .arg("-Map")
        .arg(temp.path().join("gnu.map"))
        .arg("-o")
        .arg(temp.path().join("gnu"))
        .args(inputs)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );
    let ours = fs::read_to_string(our_map).unwrap();
    let gnu = fs::read_to_string(temp.path().join("gnu.map")).unwrap();
    assert_eq!(archive_section(&ours), archive_section(&gnu));
    assert!(archive_section(&ours).contains("libc.a(libc-start.o)\n"));
    assert!(archive_section(&ours).contains(&format!(
        "{} (__libc_start_main)\n",
        toolchain.crt1.display()
    )));
    run_executable(&temp.path().join("ours"))
        .success()
        .stdout("hello, glibc\n");
}
