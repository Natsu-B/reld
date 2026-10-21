/// Return the lines of a link map's archive section, ending with newlines.
///
/// The section lists each pulled archive member with the file and symbol that
/// needed it. The next blank line ends it. Only trailing whitespace is ignored;
/// paths, order, wrapping and indentation must agree with GNU ld.
#[allow(dead_code)]
pub fn archive_section(map: &str) -> String {
    let mut lines = map.lines();
    assert_eq!(
        lines.next(),
        Some("Archive member included to satisfy reference by file (symbol)")
    );
    assert_eq!(lines.next(), Some(""));
    lines
        .take_while(|line| !line.trim_end().is_empty())
        .map(|line| format!("{}\n", line.trim_end()))
        .collect()
}
