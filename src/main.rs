use std::fs::File;
use std::path;

use json_carver::{Carver, Reader, Writer, DEFAULT_MIN_JSON_SIZE};

use clap::Parser;

/// Find JSON strings in a file faster than strings(1), print structurally
/// valid ones and report corrupted ones.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// File to carve. Reads from stdin by default.
    #[arg(short, long)]
    input: Option<path::PathBuf>,

    /// Where to write the JSON strings. Writes to stdout by default.
    #[arg(short, long)]
    output: Option<path::PathBuf>,

    /// Where to write the report for corrupted strings. Writes to stderr by default.
    #[arg(short, long)]
    report: Option<path::PathBuf>,

    /// Replace newlines in JSON strings with a space (" ") character.
    #[arg(long, default_value_t = false)]
    replace_newlines: bool,

    /// Minimum size of JSON strings to report.
    #[arg(long, default_value_t = DEFAULT_MIN_JSON_SIZE)]
    min_size: usize,

    /// Attempt to fix incomplete JSON strings by returning an incomplete, but
    /// structurally valid, version of them.
    #[arg(long, default_value_t = false)]
    fix_incomplete: bool,
}

fn main() {
    let args = Args::parse();
    let reader = match args.input {
        None => Reader::from_stdin(),
        Some(p) => Reader::from_file(File::open(&p).unwrap(), None),
    };
    let json_writer = match args.output {
        None => Writer::to_stdout(),
        Some(p) => Writer::to_file(File::create(&p).unwrap(), None),
    };
    let report_writer = match args.report {
        None => Writer::to_stderr(),
        Some(p) => Writer::to_file(File::create(&p).unwrap(), None),
    };
    let mut carver = Carver::new(reader, json_writer, report_writer, None, None);
    carver.min_size = args.min_size;
    carver.fix_incomplete = args.fix_incomplete;
    carver.replace_newlines(args.replace_newlines);
    carver.parse();
}
