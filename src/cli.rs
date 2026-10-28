//! Read command-line options for the link.
//!
//! [`parse`] turns process arguments into [`Args`]: input paths in search order,
//! archive group ranges, an output path, an optional script, [`report::Options`],
//! and a pending warning for an unclosed group. Groups let archive search return
//! to earlier archives until a full pass pulls nothing, as GNU ld does.
//! GNU ld accepts `-Map` with one dash. We change that spelling for clap before
//! parsing; `--` still ends option parsing.
//!
//! References: [GNU ld options](https://sourceware.org/binutils/docs/ld/Options.html),
//! including `--start-group` and `--end-group`.

use std::{ffi::OsString, ops::Range, os::unix::ffi::OsStringExt};

use clap::{ArgAction, CommandFactory, FromArgMatches, Parser, error::ErrorKind};

use crate::report;

/// Input order matters: only groups revisit archives for later references.
///
/// Keep clap's command description empty so Rust docs do not change CLI help.
#[derive(Parser, Debug)]
#[command(about = None, long_about = None)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) report: report::Options,

    /// Output file
    #[clap(short, long, required = true)]
    pub(crate) output: String,

    /// Linker script (replaces the built-in static x86-64 script)
    #[clap(short = 'T', long, value_name = "FILE")]
    pub(crate) script: Option<String>,

    /// Input file
    #[clap(value_name = "InputFile", required = true)]
    pub(crate) input: Vec<String>,

    // Append keeps one clap index per use; Count would keep only the last one.
    /// Start a group of archives searched again until no new symbols are found
    #[arg(long, short = '(', action = ArgAction::Append, num_args = 0, default_missing_value = "true")]
    start_group: Vec<bool>,

    /// End a group of archives
    #[arg(long, short = ')', action = ArgAction::Append, num_args = 0, default_missing_value = "true")]
    end_group: Vec<bool>,

    /// Half-open ranges of `input` positions, sorted and not overlapping.
    #[arg(skip)]
    pub(crate) groups: Vec<Range<usize>>,

    /// The last group had no `--end-group`. `main()` warns once logging is set.
    #[arg(skip)]
    pub(crate) missing_end_group: bool,

    /// Debug Level 0: None, 1: Error, 2: Warning, 3: Info, 4: Debug
    #[clap(short, long, default_value_t = 2)]
    pub(crate) debug: u8,
}

/// Read process arguments; clap prints help or errors and exits when needed.
pub(crate) fn parse() -> Args {
    parse_from(std::env::args_os()).unwrap_or_else(|error| error.exit())
}

fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<Args, clap::Error> {
    let matches = Args::command().try_get_matches_from(gnu_style_arguments(args))?;
    let mut args = Args::from_arg_matches(&matches)?;
    // clap separates flags from inputs. Its indices preserve their relative
    // order even though they are not positions in the original argv.
    let mut boundaries = Vec::new();
    for (name, starts) in [("start_group", true), ("end_group", false)] {
        if let Some(indices) = matches.indices_of(name) {
            boundaries.extend(indices.map(|index| (index, starts)));
        }
    }
    boundaries.sort_unstable_by_key(|&(index, _)| index);
    let mut inputs = matches.indices_of("input").into_iter().flatten().peekable();
    let mut position = 0;
    let mut start = None;
    for (index, starts) in boundaries {
        while inputs.peek().is_some_and(|&input| input < index) {
            inputs.next();
            position += 1;
        }
        if starts {
            // GNU ld 2.46 accepts nesting; old versions reject it. We keep
            // groups flat so each range has a single search boundary.
            if start.is_some() {
                return Err(Args::command().error(
                    ErrorKind::ArgumentConflict,
                    "nested --start-group is not supported",
                ));
            }
            start = Some(position);
        } else {
            let first = start.take().ok_or_else(|| {
                Args::command().error(ErrorKind::ArgumentConflict, "group ended before it began")
            })?;
            args.groups.push(first..position);
        }
    }
    if let Some(first) = start {
        args.groups.push(first..args.input.len());
        args.missing_end_group = true;
    }
    Ok(args)
}

fn gnu_style_arguments(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut positional = false;
    args.into_iter()
        .map(|arg| {
            if arg == "--" {
                positional = true;
            }
            if !positional {
                if arg == "-Map" {
                    return "--map".into();
                }
                if let Some(path) = arg.as_encoded_bytes().strip_prefix(b"-Map=") {
                    let mut option = b"--map=".to_vec();
                    option.extend_from_slice(path);
                    return OsString::from_vec(option);
                }
            }
            arg
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Check group boundaries, diagnostics, and GNU option spellings.

    use super::*;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        parse_from(args.iter().map(OsString::from))
    }

    #[test]
    fn group_ranges_follow_inputs_among_other_options() {
        let args = parse(&[
            "reld",
            "a.o",
            "--start-group",
            "x.a",
            "-o",
            "out",
            "y.a",
            "--end-group",
            "-(",
            "z.a",
            "-)",
            "w.o",
        ])
        .unwrap();
        assert_eq!(args.input, ["a.o", "x.a", "y.a", "z.a", "w.o"]);
        assert_eq!(args.groups, [1..3, 3..4]);
        assert!(!args.missing_end_group);
    }

    #[test]
    fn ending_a_group_before_it_begins_is_an_error() {
        let error = parse(&["reld", "-o", "out", "missing.o", "--end-group"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        assert!(error.to_string().contains("group ended before it began"));
    }

    #[test]
    fn nested_groups_are_an_error() {
        let error = parse(&[
            "reld",
            "-o",
            "out",
            "--start-group",
            "missing.o",
            "-(",
            "-)",
            "--end-group",
        ])
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("nested --start-group is not supported")
        );
    }

    #[test]
    fn an_unclosed_group_ends_after_the_last_input_and_records_a_warning() {
        let args = parse(&["reld", "-o", "out", "a.o", "--start-group", "x.a", "y.a"]).unwrap();
        assert_eq!(args.groups, [1..3]);
        assert!(args.missing_end_group);
        assert_eq!(args.debug, 2);
    }

    #[test]
    fn group_options_after_the_positional_boundary_are_file_names() {
        let args = parse(&[
            "reld",
            "-o",
            "out",
            "--",
            "--start-group",
            "-Map",
            "--end-group",
        ])
        .unwrap();
        assert_eq!(args.input, ["--start-group", "-Map", "--end-group"]);
        assert!(args.groups.is_empty());
        assert!(!args.missing_end_group);
    }

    #[test]
    fn empty_groups_keep_their_positions() {
        let args = parse(&["reld", "-(", "-)", "a.o", "-(", "-)", "-o", "out"]).unwrap();
        assert_eq!(args.groups, [0..0, 1..1]);
    }
}
