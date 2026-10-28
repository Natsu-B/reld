use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

use assert_cmd::Command;
use elf::Elf64;
use tempfile::TempDir;

pub fn assert_linux_host() {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "GNU as/ld based integration tests require Linux",
    );
}

#[allow(dead_code)]
pub fn write_asm_source(dir: &TempDir, file_name: &str, source: &str) -> PathBuf {
    let path = dir.path().join(file_name);
    fs::write(&path, source).unwrap_or_else(|err| {
        panic!("failed to write assembly source {}: {err}", path.display());
    });
    path
}

#[allow(dead_code)]
pub fn assemble_object(dir: &TempDir, stem: &str, source: &str) -> PathBuf {
    assert_linux_host();

    let asm_path = write_asm_source(dir, &format!("{stem}.s"), source);
    let object_path = dir.path().join(format!("{stem}.o"));

    let mut command = StdCommand::new("as");
    command
        .arg("--64")
        .arg("-o")
        .arg(&object_path)
        .arg(&asm_path);
    run_tool(command, &format!("assemble {}", object_path.display()));

    object_path
}

#[allow(dead_code)]
pub fn compile_c_object(dir: &TempDir, stem: &str, source: &str) -> PathBuf {
    assert_linux_host();

    let c_path = dir.path().join(format!("{stem}.c"));
    fs::write(&c_path, source).unwrap_or_else(|err| {
        panic!("failed to write C source {}: {err}", c_path.display());
    });
    let object_path = dir.path().join(format!("{stem}.o"));

    let mut command = StdCommand::new("gcc");
    command
        .arg("-c")
        .arg("-O2")
        .arg("-fno-pie")
        .arg("-static")
        .arg("-fno-stack-protector")
        .arg("-isystem")
        .arg(require_env_dir("GLIBC_INCLUDE_DIR"))
        .arg("-o")
        .arg(&object_path)
        .arg(&c_path);
    run_tool(command, &format!("compile {}", object_path.display()));

    object_path
}

#[allow(dead_code)]
pub struct GlibcStaticToolchain {
    pub crt1: PathBuf,
    pub crti: PathBuf,
    pub crtn: PathBuf,
    pub crtbegin_t: PathBuf,
    pub crtend: PathBuf,
    pub libc: PathBuf,
    pub libgcc: PathBuf,
    pub libgcc_eh: PathBuf,
}

#[allow(dead_code)]
impl GlibcStaticToolchain {
    /// Resolve the libc.a/libgcc.a cycle without a group by repeating libc.a.
    pub fn link_inputs<'a>(&'a self, objects: &[&'a Path]) -> Vec<&'a Path> {
        let mut inputs = vec![
            self.crt1.as_path(),
            self.crti.as_path(),
            self.crtbegin_t.as_path(),
        ];
        inputs.extend_from_slice(objects);
        inputs.extend([
            self.libc.as_path(),
            self.libgcc.as_path(),
            self.libgcc_eh.as_path(),
            self.libc.as_path(),
            self.crtend.as_path(),
            self.crtn.as_path(),
        ]);
        inputs
    }

    /// Inputs and archive group options in the order `gcc -static` uses.
    pub fn grouped_link_inputs(&self, objects: &[&Path]) -> Vec<OsString> {
        let mut inputs = vec![
            self.crt1.clone().into_os_string(),
            self.crti.clone().into_os_string(),
            self.crtbegin_t.clone().into_os_string(),
        ];
        inputs.extend(objects.iter().map(|object| object.as_os_str().to_owned()));
        inputs.extend([
            "--start-group".into(),
            self.libgcc.clone().into_os_string(),
            self.libgcc_eh.clone().into_os_string(),
            self.libc.clone().into_os_string(),
            "--end-group".into(),
            self.crtend.clone().into_os_string(),
            self.crtn.clone().into_os_string(),
        ]);
        inputs
    }
}

#[allow(dead_code)]
pub fn glibc_static_toolchain() -> GlibcStaticToolchain {
    let lib_dir = require_env_dir("GLIBC_STATIC_LIB_DIR");
    let crt_dir = require_env_dir("GLIBC_CRT_DIR");
    let libgcc_dir = require_env_dir("LIBGCC_DIR");

    GlibcStaticToolchain {
        crt1: require_file(crt_dir.join("crt1.o")),
        crti: require_file(crt_dir.join("crti.o")),
        crtn: require_file(crt_dir.join("crtn.o")),
        crtbegin_t: require_file(libgcc_dir.join("crtbeginT.o")),
        crtend: require_file(libgcc_dir.join("crtend.o")),
        libc: require_file(lib_dir.join("libc.a")),
        libgcc: require_file(libgcc_dir.join("libgcc.a")),
        libgcc_eh: require_file(libgcc_dir.join("libgcc_eh.a")),
    }
}

fn require_env_dir(name: &str) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| {
        panic!("{name} is not set; run the tests inside `nix develop`");
    });
    PathBuf::from(value)
}

fn require_file(path: PathBuf) -> PathBuf {
    assert!(
        path.is_file(),
        "{} does not exist; run the tests inside `nix develop`",
        path.display(),
    );
    path
}

#[allow(dead_code)]
pub fn create_archive(dir: &TempDir, stem: &str, members: &[&Path]) -> PathBuf {
    assert_linux_host();

    let archive_path = dir.path().join(format!("{stem}.a"));

    let mut command = StdCommand::new("ar");
    command.arg("crs").arg(&archive_path);
    for member in members {
        command.arg(member);
    }
    run_tool(command, &format!("archive {}", archive_path.display()));

    archive_path
}

/// Make a thin archive with `ar crsT`, running in `dir` so `ar` stores each
/// member path relative to the archive's directory, as a build tree does.
#[allow(dead_code)]
pub fn create_thin_archive(dir: &TempDir, archive: &str, members: &[&str]) -> PathBuf {
    assert_linux_host();

    let mut command = StdCommand::new("ar");
    command
        .current_dir(dir.path())
        .arg("crsT")
        .arg(archive)
        .args(members);
    run_tool(command, &format!("archive {archive}"));

    dir.path().join(archive)
}

#[allow(dead_code)]
pub fn link_executable_input(dir: &TempDir, output_name: &str, inputs: &[&Path]) -> PathBuf {
    assert_linux_host();

    let output_path = dir.path().join(output_name);

    let mut command = StdCommand::new("ld");
    command
        .arg("-o")
        .arg(&output_path)
        .arg("-e")
        .arg("_start")
        .arg("-no-pie");
    for input in inputs {
        command.arg(input);
    }
    run_tool(command, &format!("link {}", output_path.display()));

    output_path
}

#[allow(dead_code)]
pub fn link_static_executable_input(dir: &TempDir, output_name: &str, inputs: &[&Path]) -> PathBuf {
    assert_linux_host();

    let output_path = dir.path().join(output_name);
    let mut command = StdCommand::new("ld");
    command
        .arg("-static")
        .arg("-o")
        .arg(&output_path)
        .args(inputs);
    run_tool(command, &format!("link {}", output_path.display()));

    output_path
}

pub fn cargo_linker() -> Command {
    let mut command = Command::cargo_bin("reld").unwrap_or_else(|err| {
        panic!("failed to locate reld test binary: {err}");
    });
    command.env("NO_COLOR", "1");
    command.env("RAYON_NUM_THREADS", "1");
    command
}

#[allow(dead_code)]
pub fn cargo_linker_with_debug(debug: u8) -> Command {
    let mut command = cargo_linker();
    command.arg("--debug").arg(debug.to_string());
    command
}

#[allow(dead_code)]
pub fn run_executable(path: &Path) -> assert_cmd::assert::Assert {
    Command::new(path).assert()
}

#[allow(dead_code)]
pub fn read_output_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("failed to read output file {}: {err}", path.display());
    })
}

#[allow(dead_code)]
pub fn parse_elf64<'a>(bytes: &'a [u8]) -> Elf64<'a> {
    Elf64::new(bytes).unwrap_or_else(|err| {
        panic!("failed to parse ELF output: {err:#}");
    })
}

fn run_tool(mut command: StdCommand, action: &str) -> std::process::Output {
    let rendered = format!("{command:?}");
    let output = command.output().unwrap_or_else(|err| {
        panic!("failed to spawn {action} with {rendered}: {err}");
    });

    if !output.status.success() {
        panic!(
            "{action} failed\ncommand: {rendered}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    output
}

#[allow(dead_code)]
pub fn readelf_program_headers(path: &Path) -> String {
    let mut command = StdCommand::new("readelf");
    command.arg("-lW").arg(path);
    let output = run_tool(
        command,
        &format!("read program headers of {}", path.display()),
    );
    String::from_utf8(output.stdout).unwrap()
}
