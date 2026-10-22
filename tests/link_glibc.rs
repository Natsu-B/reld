#![cfg(target_os = "linux")]

mod common;

use std::collections::BTreeSet;

use common::toolchain::{
    cargo_linker_with_debug, compile_c_object, glibc_static_toolchain,
    link_static_executable_input, parse_elf64, read_output_bytes, run_executable,
};
use elf::{
    Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType, ElfFileType,
    ElfMachineType, ElfProgramHeaderType,
};
use tempfile::tempdir;

const HELLO_SOURCE: &str = r#"
#include <stdio.h>

int main(void) {
    puts("hello, glibc");
    return 0;
}
"#;

const HELLO_STDOUT: &str = "hello, glibc\n";

/// Sanity check for the toolchain itself: GNU ld must be able to link the same inputs.
#[test]
fn gnu_ld_links_static_glibc_hello_world() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(&temp, "main", HELLO_SOURCE);
    let output =
        link_static_executable_input(&temp, "hello_ld", &toolchain.link_inputs(&[main.as_path()]));

    run_executable(&output).success().stdout(HELLO_STDOUT);
}

#[test]
fn links_static_glibc_hello_world() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(&temp, "main", HELLO_SOURCE);
    let output = temp.path().join("hello");

    let mut command = cargo_linker_with_debug(1);
    command.arg("-o").arg(&output);
    for input in toolchain.link_inputs(&[main.as_path()]) {
        command.arg(input);
    }
    command.assert().success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    assert_eq!(elf.elf_type(), ElfFileType::ET_EXEC);
    assert_eq!(elf.arch(), ElfMachineType::EM_X86_64);
    assert!(
        elf.sections()
            .filter(|section| section.flags().get(elf::Elf64SectionFlags::SHF_ALLOC) != 0)
            .all(|section| section.size() != 0)
    );
    assert!(
        !elf.sections()
            .any(|section| section.name().unwrap() == ".note.gnu.property")
    );
    assert!(
        elf.sections()
            .any(|section| section.name().unwrap() == ".note.ABI-tag")
    );

    run_executable(&output).success().stdout(HELLO_STDOUT);
    let baseline =
        link_static_executable_input(&temp, "hello_ld", &toolchain.link_inputs(&[main.as_path()]));
    let baseline_bytes = read_output_bytes(&baseline);
    let baseline_elf = parse_elf64(&baseline_bytes);
    let table = elf
        .sections()
        .find(|section| section.name().unwrap() == ".symtab")
        .unwrap();
    let init_array = elf
        .sections()
        .find(|section| section.name().unwrap() == ".init_array")
        .unwrap();
    for marker in ["__preinit_array_start", "__preinit_array_end"] {
        let symbol = table
            .symbols()
            .unwrap()
            .find(|symbol| symbol.name().unwrap() == marker)
            .unwrap();
        assert_eq!(
            symbol.section_idx(),
            Elf64SymbolSectionIdx::Index(init_array.idx())
        );
        assert_eq!(symbol.value(), init_array.address());
    }
    let globals = |elf: &elf::Elf64| {
        let table = elf
            .sections()
            .find(|section| section.name().unwrap() == ".symtab")
            .unwrap();
        table
            .symbols()
            .unwrap()
            .filter(|symbol| {
                symbol.info().get_enum(Elf64SymbolInfo::st_bind)
                    != Some(Elf64SymbolBinding::STB_LOCAL)
                    && symbol.section_idx() != Elf64SymbolSectionIdx::Undefined
            })
            .map(|symbol| symbol.name().unwrap().to_string())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(globals(&elf), globals(&baseline_elf));
    let symbol_values = |image: &elf::Elf64| {
        let table = image
            .sections()
            .find(|section| section.name().unwrap() == ".symtab")
            .unwrap();
        table
            .symbols()
            .unwrap()
            .map(|symbol| (symbol.name().unwrap().to_string(), symbol.value()))
            .collect::<std::collections::HashMap<_, _>>()
    };
    for image in [&elf, &baseline_elf] {
        let relocations = image
            .sections()
            .find(|section| section.name().unwrap() == ".rela.plt")
            .unwrap();
        assert_eq!(relocations.entry_size(), 24);
        assert!(
            relocations
                .rela()
                .unwrap()
                .all(|relocation| relocation.info().ty == 37)
        );
        let symbols = symbol_values(image);
        assert_eq!(
            symbols["__rela_iplt_end"] - symbols["__rela_iplt_start"],
            relocations.size()
        );
    }
    // crtbeginT.o adds one entry to each array and libc.a may add more, so the
    // sizes depend on the toolchain. Expect the sizes GNU ld chose.
    let array_sizes = |image: &elf::Elf64| {
        let symbols = symbol_values(image);
        [
            symbols["__init_array_end"] - symbols["__init_array_start"],
            symbols["__fini_array_end"] - symbols["__fini_array_start"],
        ]
    };
    assert_eq!(array_sizes(&elf), array_sizes(&baseline_elf));
    let relocation_count = |image: &elf::Elf64| {
        image
            .sections()
            .find(|section| section.name().unwrap() == ".rela.plt")
            .unwrap()
            .size()
            / 24
    };
    assert_eq!(relocation_count(&elf), relocation_count(&baseline_elf));
}

#[test]
fn links_static_glibc_thread_local_variables() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "tls",
        r#"
#include <pthread.h>
#include <stdio.h>

__thread volatile int initialized __attribute__((aligned(64))) = 17;
__thread volatile int zero_initialized;

struct main_tls {
    volatile int *initialized;
    volatile int *zero_initialized;
};

static void *worker(void *argument) {
    struct main_tls *main_tls = argument;
    if (initialized != 17 || zero_initialized != 0 ||
        &initialized == main_tls->initialized ||
        &zero_initialized == main_tls->zero_initialized)
        return NULL;
    printf("thread TLS initial: %d %d\n", initialized, zero_initialized);
    initialized = 101;
    zero_initialized = 200;
    if (initialized != 101 || zero_initialized != 200 ||
        *main_tls->initialized != 31 || *main_tls->zero_initialized != 7)
        return NULL;
    printf("thread TLS changed: %d %d\n", initialized, zero_initialized);
    return argument;
}

int main(void) {
    if (initialized != 17 || zero_initialized != 0)
        return 1;
    printf("main TLS initial: %d %d\n", initialized, zero_initialized);
    initialized = 31;
    zero_initialized = 7;
    struct main_tls main_tls = { &initialized, &zero_initialized };
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, &main_tls) != 0)
        return 2;
    void *result = NULL;
    if (pthread_join(thread, &result) != 0 || result != &main_tls)
        return 3;
    if (initialized != 31 || zero_initialized != 7)
        return 4;
    printf("main TLS unchanged: %d %d\n", initialized, zero_initialized);
    return 0;
}
"#,
    );
    let inputs = toolchain.link_inputs(&[main.as_path()]);
    let baseline = link_static_executable_input(&temp, "tls_ld", &inputs);
    let output = temp.path().join("tls");
    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .args(&inputs)
        .assert()
        .success();

    let stdout = concat!(
        "main TLS initial: 17 0\n",
        "thread TLS initial: 17 0\n",
        "thread TLS changed: 101 200\n",
        "main TLS unchanged: 31 7\n",
    );
    let mut tls_sizes = Vec::new();
    for executable in [&baseline, &output] {
        let bytes = read_output_bytes(executable);
        let elf = parse_elf64(&bytes);
        let tls = elf
            .program_headers()
            .find(|header| header.segment_type() == ElfProgramHeaderType::PT_TLS)
            .unwrap();
        assert!(tls.file_size() > 0);
        assert!(tls.mem_size() > tls.file_size());
        assert_eq!(tls.align(), 64);
        let tdata = elf
            .sections()
            .find(|section| section.name().unwrap() == ".tdata")
            .unwrap();
        let tbss = elf
            .sections()
            .find(|section| section.name().unwrap() == ".tbss")
            .unwrap();
        assert_eq!(tdata.address(), tls.vaddr());
        assert_eq!(tdata.size(), tls.file_size());
        assert_eq!(
            tbss.address(),
            (tdata.address() + tdata.size()).next_multiple_of(tbss.align())
        );
        assert_eq!(tbss.address() + tbss.size(), tls.vaddr() + tls.mem_size());
        let table = elf
            .sections()
            .find(|section| section.name().unwrap() == ".symtab")
            .unwrap();
        let mut max_tls_end = 0;
        for symbol in table.symbols().unwrap().filter(|symbol| {
            symbol.info().get_enum(Elf64SymbolInfo::st_type) == Some(Elf64SymbolType::STT_TLS)
        }) {
            let Elf64SymbolSectionIdx::Index(index) = symbol.section_idx() else {
                continue;
            };
            let section = elf
                .sections()
                .find(|section| section.idx() == index)
                .unwrap();
            let address = tls.vaddr() + symbol.value();
            assert!(address >= section.address());
            assert!(address + symbol.size() <= section.address() + section.size());
            let align = match symbol.name().unwrap() {
                "initialized" => 64,
                "zero_initialized" | "errno" | "__libc_errno" => 4,
                _ => 8,
            };
            assert_eq!(symbol.value() % align, 0);
            max_tls_end = max_tls_end.max(symbol.value() + symbol.size());
        }
        assert_eq!(max_tls_end, tls.mem_size());
        // Matching archive extraction order also preserves padding between
        // TLS inputs, so compare the exact template size with GNU ld.
        tls_sizes.push(tls.mem_size());
        run_executable(executable).success().stdout(stdout);
    }
    assert_eq!(tls_sizes[0], tls_sizes[1]);
}

#[test]
fn links_static_glibc_constructors_destructors_and_atexit() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "lifecycle",
        r#"
#include <stdio.h>
#include <stdlib.h>

// Declare priorities out of order so input order cannot satisfy the test.
__attribute__((constructor(200))) static void init_200(void) {
    puts("constructor 200");
}
__attribute__((constructor(101))) static void init_101(void) {
    puts("constructor 101");
}
__attribute__((constructor)) static void init_default(void) {
    puts("constructor default");
}

__attribute__((destructor(200))) static void fini_200(void) {
    puts("destructor 200");
}
__attribute__((destructor(101))) static void fini_101(void) {
    puts("destructor 101");
}
__attribute__((destructor)) static void fini_default(void) {
    puts("destructor default");
}

static void exit_first(void) { puts("atexit first"); }
static void exit_second(void) { puts("atexit second"); }

int main(void) {
    puts("main");
    if (atexit(exit_first) != 0 || atexit(exit_second) != 0)
        return 1;
    return 0;
}
"#,
    );
    let inputs = toolchain.link_inputs(&[main.as_path()]);
    let baseline = link_static_executable_input(&temp, "lifecycle_ld", &inputs);
    let output = temp.path().join("lifecycle");
    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .args(&inputs)
        .assert()
        .success();

    let stdout = concat!(
        "constructor 101\n",
        "constructor 200\n",
        "constructor default\n",
        "main\n",
        "atexit second\n",
        "atexit first\n",
        "destructor default\n",
        "destructor 200\n",
        "destructor 101\n",
    );
    run_executable(&baseline).success().stdout(stdout);
    run_executable(&output).success().stdout(stdout);
}

#[test]
fn links_static_glibc_ifunc_buffer_functions() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "buffers",
        r#"
#include <stdio.h>
#include <string.h>

// Volatile pointers preserve real libc calls under compile_c_object's -O2.
static void *(*volatile copy_bytes)(void *, const void *, size_t) = memcpy;
static void *(*volatile move_bytes)(void *, const void *, size_t) = memmove;
static void *(*volatile fill_bytes)(void *, int, size_t) = memset;
static size_t (*volatile string_length)(const char *) = strlen;
static char *(*volatile find_character)(const char *, int) = strchr;

int main(void) {
    const size_t sizes[] = { 0, 1, 7, 16, 31, 64, 255, 1024, 4096 };
    unsigned char source[4096 + 32], buffer[4096 + 32];
    for (size_t i = 0; i < sizeof(source); ++i)
        source[i] = 'a' + i % 23;

    for (size_t test = 0; test < sizeof(sizes) / sizeof(sizes[0]); ++test) {
        size_t n = sizes[test];
        if (fill_bytes(buffer, 0x5a, sizeof(buffer)) != buffer ||
            copy_bytes(buffer + 3, source + 1, n) != buffer + 3)
            return 1;
        for (size_t i = 0; i < sizeof(buffer); ++i)
            if (buffer[i] != (i >= 3 && i < n + 3 ? source[i - 2] : 0x5a))
                return 2;

        // Exercise overlapping moves in both directions, with unaligned pointers.
        copy_bytes(buffer, source, sizeof(buffer));
        if (move_bytes(buffer + 3, buffer + 1, n) != buffer + 3)
            return 3;
        for (size_t i = 0; i < sizeof(buffer); ++i)
            if (buffer[i] != source[i >= 3 && i < n + 3 ? i - 2 : i])
                return 4;
        copy_bytes(buffer, source, sizeof(buffer));
        if (move_bytes(buffer + 1, buffer + 3, n) != buffer + 1)
            return 5;
        for (size_t i = 0; i < sizeof(buffer); ++i)
            if (buffer[i] != source[i >= 1 && i < n + 1 ? i + 2 : i])
                return 6;

        if (fill_bytes(buffer + 3, 0xa5, n) != buffer + 3)
            return 7;
        for (size_t i = 0; i < sizeof(buffer); ++i) {
            unsigned char expected = i >= 3 && i < n + 3 ? 0xa5 :
                source[i >= 1 && i < n + 1 ? i + 2 : i];
            if (buffer[i] != expected)
                return 8;
        }

        char *text = (char *)buffer + 3;
        fill_bytes(text, 'a', n);
        if (n != 0)
            text[n - 1] = 'z';
        text[n] = '\0';
        if (string_length(text) != n ||
            find_character(text, 'z') != (n == 0 ? NULL : text + n - 1) ||
            find_character(text, '!') != NULL ||
            find_character(text, '\0') != text + n)
            return 9;
    }
    puts("libc IFUNC buffers: ok");
    return 0;
}
"#,
    );
    let output = temp.path().join("buffers");
    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .args(toolchain.link_inputs(&[main.as_path()]))
        .assert()
        .success();
    run_executable(&output)
        .success()
        .stdout("libc IFUNC buffers: ok\n");
}

#[test]
fn links_static_glibc_user_defined_ifunc() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "user_ifunc",
        r#"
#include <stdio.h>

static volatile int resolver_calls;
static volatile int selector = 1;
static int implementation(int value) { return value * 2 + 2; }
static int fallback(int value) { return value; }

// Resolvers run before libc initialization and must not call libc functions.
static int (*resolve_transform(void))(int) {
    ++resolver_calls;
    return selector ? implementation : fallback;
}
int transform(int) __attribute__((ifunc("resolve_transform")));
static int (*volatile indirect_transform)(int) = transform;

int main(void) {
    if (resolver_calls != 1 || transform(20) != 42 || transform(0) != 2 ||
        indirect_transform(5) != 12 || resolver_calls != 1)
        return 1;
    puts("user IFUNC: ok");
    return 0;
}
"#,
    );
    let inputs = toolchain.link_inputs(&[main.as_path()]);
    let baseline = link_static_executable_input(&temp, "user_ifunc_ld", &inputs);
    let output = temp.path().join("user_ifunc");
    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .args(&inputs)
        .assert()
        .success();
    run_executable(&baseline)
        .success()
        .stdout("user IFUNC: ok\n");
    run_executable(&output).success().stdout("user IFUNC: ok\n");
}

#[test]
fn links_static_glibc_printf_buffering_and_exit() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "printf",
        r#"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    static char buffer[4096];
    if (setvbuf(stdout, buffer, _IOFBF, sizeof(buffer)) != 0)
        return 1;
    if (printf("integer=%d string=%s float=%.2f\n", -42, "glibc", 3.25) !=
        sizeof("integer=-42 string=glibc float=3.25\n") - 1)
        return 2;
    if (fputs("flushed explicitly\n", stdout) == EOF || fflush(stdout) != 0)
        return 4;
    if (fputs("flushed on exit", stdout) == EOF)
        return 5;
    exit(3);
}
"#,
    );
    let output = temp.path().join("printf");
    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .args(toolchain.link_inputs(&[main.as_path()]))
        .assert()
        .success();
    run_executable(&output).code(3).stdout(concat!(
        "integer=-42 string=glibc float=3.25\n",
        "flushed explicitly\n",
        "flushed on exit",
    ));
}

#[test]
fn links_static_glibc_errno_after_a_failing_syscall() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(
        &temp,
        "errno",
        r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    errno = 0;
    // A child of /dev/null cannot exist, independent of the host filesystem.
    int fd = open("/dev/null/my_linker_nonexistent", O_RDONLY);
    int saved_errno = errno;
    if (fd != -1) {
        close(fd);
        return 1;
    }
    if (saved_errno != ENOTDIR)
        return 2;
    errno = EDOM;
    if (errno != EDOM)
        return 3;
    puts("open failed: ENOTDIR; errno writable: ok");
    return 0;
}
"#,
    );
    let output = temp.path().join("errno");
    cargo_linker_with_debug(1)
        .arg("-o")
        .arg(&output)
        .args(toolchain.link_inputs(&[main.as_path()]))
        .assert()
        .success();
    run_executable(&output)
        .success()
        .stdout("open failed: ENOTDIR; errno writable: ok\n");
}
