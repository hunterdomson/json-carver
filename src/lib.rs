//! JSON Carver
//!
//! Carve JSON structs from a binary stream of data.

#![deny(
    ambiguous_glob_reexports,
    anonymous_parameters,
    array_into_iter,
    asm_sub_register,
    bad_asm_style,
    bare_trait_objects,
    break_with_label_and_loop,
    clashing_extern_declarations,
    coherence_leak_check,
    confusable_idents,
    const_evaluatable_unchecked,
    const_item_mutation,
    dead_code,
    deprecated,
    deprecated_where_clause_location,
    deref_into_dyn_supertrait,
    deref_nullptr,
    drop_bounds,
    dropping_copy_types,
    dropping_references,
    duplicate_macro_attributes,
    dyn_drop,
    ellipsis_inclusive_range_patterns,
    exported_private_dependencies,
    for_loops_over_fallibles,
    forbidden_lint_groups,
    forgetting_copy_types,
    forgetting_references,
    function_item_references,
    improper_ctypes,
    improper_ctypes_definitions,
    incomplete_features,
    inline_no_sanitize,
    invalid_doc_attributes,
    invalid_macro_export_arguments,
    invalid_value,
    irrefutable_let_patterns,
    large_assignments,
    late_bound_lifetime_arguments,
    legacy_derive_helpers,
    map_unit_fn,
    missing_docs,
    named_arguments_used_positionally,
    no_mangle_generic_items,
    non_camel_case_types,
    non_fmt_panics,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    opaque_hidden_inferred_bound,
    overlapping_range_endpoints,
    path_statements,
    redundant_semicolons,
    renamed_and_removed_lints,
    repr_transparent_external_private_fields,
    semicolon_in_expressions_from_macros,
    special_module_name,
    stable_features,
    suspicious_double_ref_op,
    trivial_bounds,
    //trivial_casts,
    trivial_numeric_casts,
    type_alias_bounds,
    tyvar_behind_raw_pointer,
    uncommon_codepoints,
    unconditional_recursion,
    undefined_naked_function_abi,
    unexpected_cfgs,
    ungated_async_fn_track_caller,
    uninhabited_static,
    unknown_lints,
    unnameable_test_items,
    unreachable_code,
    unreachable_patterns,
    unsafe_code,
    unstable_features,
    unstable_name_collisions,
    unstable_syntax_pre_expansion,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_braces,
    unused_braces,
    unused_comparisons,
    unused_doc_comments,
    unused_features,
    unused_features,
    unused_import_braces,
    unused_imports,
    unused_imports,
    unused_labels,
    unused_labels,
    unused_macros,
    unused_macros,
    unused_must_use,
    unused_mut,
    unused_mut,
    unused_parens,
    unused_parens,
    unused_qualifications,
    unused_unsafe,
    unused_unsafe,
    unused_variables,
    warnings,
    while_true
)]

use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, BufWriter, Read, StderrLock, StdinLock, StdoutLock, Write};

use memchr;

// Incrementally extend the internal buffer by this amount of bytes, whenever
// a JSON string no longer fits in it.
const BUF_EXTEND_SIZE: usize = 4 << 20; // 4MiB

// The maximum identation depth of the JSON string that will be handled.
const DEFAULT_MAX_IDENT_DEPTH: usize = 4 << 20;

/// The minimum size of a JSON string that we will report.
pub const DEFAULT_MIN_JSON_SIZE: usize = 4;

// Constants for parsing JSON strings.
// From https://www.rfc-editor.org/rfc/rfc8259#section-2
//
// Structural characters
const CHAR_LEFT_SQUARE_BRACKET: u8 = 0x5B; // {
const CHAR_LEFT_CURLY_BRACKET: u8 = 0x7B; // [
const CHAR_RIGHT_SQUARE_BRACKET: u8 = 0x5D; // ]
const CHAR_RIGHT_CURLY_BRACKET: u8 = 0x7D; // }
const CHAR_COLON: u8 = 0x3A; // :
const CHAR_COMMA: u8 = 0x2C; // ,

// Insignificant whitespace
const CHAR_SPACE: u8 = 0x20;
const CHAR_TAB: u8 = 0x09;
const CHAR_NEWLINE: u8 = 0x0A;
const CHAR_CARRIAGE_RETURN: u8 = 0x0D;

// Literals
const CHAR_START_FALSE: u8 = 0x66; // f
const CHAR_START_NULL: u8 = 0x6E; // n
const CHAR_START_TRUE: u8 = 0x74; // t

// Numbers
const CHAR_MINUS: u8 = 0x2D; // -
const CHAR_PLUS: u8 = 0x2B; // +
const CHAR_ZERO: u8 = 0x30; // 0
const CHAR_NINE: u8 = 0x39; // 9
const CHAR_DECIMAL: u8 = 0x2E; // .
const CHAR_EXP_LOWER: u8 = 0x65; // e
const CHAR_EXP_UPPER: u8 = 0x45; // E

// Strings
const CHAR_QUOT_MARK: u8 = 0x22; // "
const CHAR_ESCAPE: u8 = 0x5C; // \
const CHAR_SLASH: u8 = 0x2F; // /
const CHAR_ESC_BACKSPACE: u8 = 0x62; // b
const CHAR_ESC_FORM_FEED: u8 = 0x66; // f
const CHAR_ESC_LINE_FEED: u8 = 0x6E; // n
const CHAR_ESC_CARRIAGE_RETURN: u8 = 0x72; // r
const CHAR_ESC_TAB: u8 = 0x74; // t
const CHAR_U: u8 = 0x75; // u

enum Cause {
    Found(u8),
    Corrupted(u8),
    Completed,
    Exhausted,
}

fn byte_needs_escape(b: u8) -> bool {
    b < 0x1F
}

fn byte_can_escape(b: u8) -> bool {
    match b {
        CHAR_QUOT_MARK
        | CHAR_ESCAPE
        | CHAR_SLASH
        | CHAR_ESC_BACKSPACE
        | CHAR_ESC_FORM_FEED
        | CHAR_ESC_LINE_FEED
        | CHAR_ESC_CARRIAGE_RETURN
        | CHAR_ESC_TAB
        | CHAR_U => true,
        _ => false,
    }
}

fn _closing_ident(b: u8) -> u8 {
    b + 0x02
}

struct Report {
    status: Cause,
    start: usize,
    end: usize,
    partial_end: usize,
}

impl Report {
    /// Print a status report.
    ///
    /// Status reports are comma-separated CSVs with the following fields:
    ///
    /// ```text
    /// status,start,end,partial_end
    /// ```
    ///
    /// where:
    /// * `status` is either "corrupted", "exhausted", or "completed".
    /// * (`start`, `end`) is the position of the JSON string within the byte
    ///   stream, last character included.
    /// * `partial_end` is the position of the last character where the JSON
    ///    string could have ended.
    fn print(&self, writer: &mut Writer) -> Result<(), errors::Err> {
        let w = writer.mut_ref();

        let status = match self.status {
            Cause::Exhausted => "exhausted",
            Cause::Corrupted(_) => "corrupted",
            Cause::Completed => "completed",
            _ => unreachable!(),
        };
        w.write_all(
            format!(
                "{},{},{},{}\n",
                status, self.start, self.end, self.partial_end
            )
            .as_ref(),
        )
        .unwrap();
    }
}

#[derive(Debug)]
struct JsonTracker {
    cur: usize,
    partial_close_end: usize,
    ident_levels: Vec<u8>,
    cur_ident_level: usize,
    in_key: bool,
    processed: Vec<u8>,
    replace_newlines: bool,
}

impl JsonTracker {
    fn new(max_size: Option<usize>, max_ident_depth: Option<usize>) -> JsonTracker {
        let _max_size = match max_size {
            Some(size) => size,
            None => BUF_EXTEND_SIZE,
        };

        let _max_ident_depth = match max_ident_depth {
            Some(size) => size,
            None => DEFAULT_MAX_IDENT_DEPTH,
        };
        JsonTracker {
            cur: 0,
            partial_close_end: 0,
            ident_levels: vec![0u8; _max_ident_depth],
            cur_ident_level: 0,
            in_key: false,
            processed: vec![0u8; _max_size],
            replace_newlines: false,
        }
    }

    fn advance(&mut self, mut b: u8) {
        // See how ripgrep handles the "very large lines" problem:
        // https://github.com/BurntSushi/ripgrep/issues/2959
        // FIXME: Handle the case where we are asked to advance, but there is
        // no identation level remaining.
        //
        if self.replace_newlines && b == CHAR_NEWLINE {
            b = CHAR_SPACE;
        }
        if self.cur < self.processed.len() {
            self.processed[self.cur] = b;
        } else {
            self.processed.reserve(BUF_EXTEND_SIZE);
            self.processed.push(b);
        }
        self.cur += 1;
    }

    fn last_byte(&self) -> Option<u8> {
        if self.cur == 0 {
            return None;
        }

        Some(self.processed[self.cur - 1])
    }

    fn last_ident(&self) -> Option<u8> {
        if self.cur_ident_level == 0 {
            return None;
        }

        Some(self.ident_levels[self.cur_ident_level - 1])
    }

    fn add_ident(&mut self, b: u8) {
        self.cur_ident_level += 1;
        self.ident_levels[self.cur_ident_level - 1] = b;
        self.partial_close_end = self.cur;
        self.advance(b);
    }

    fn remove_ident(&mut self, expected: u8) -> Result<bool, ()> {
        match self.last_ident() {
            None => return Err(()),
            Some(ident) => {
                if ident != expected {
                    return Err(());
                }
            }
        }

        self.partial_close_end = self.cur;
        self.cur_ident_level -= 1;
        self.advance(_closing_ident(expected)); // That's the closing bracket.

        match self.cur_ident_level {
            0 => Ok(true),
            _ => Ok(false),
        }
    }

    fn quick_clean(&mut self) -> () {
        self.cur = 0;
        self.partial_close_end = 0;
        self.cur_ident_level = 0;
        self.in_key = false;
    }
}

/// Implementation of a stream reader.
pub enum Reader<'a> {
    /// A file reader
    File(BufReader<File>),
    /// An stdin sreader
    Stdin(StdinLock<'a>),
    /// A local buffer reader
    Local(BufReader<&'a [u8]>),
}

impl<'a> Reader<'a> {
    /// Create a Reader from a file.
    pub fn from_file(file: File, buf_size: Option<usize>) -> Reader<'a> {
        match buf_size {
            Some(size) => Reader::File(BufReader::with_capacity(size, file)),
            None => Reader::File(BufReader::new(file)),
        }
    }

    /// Create a Reader for the process' stdin.
    pub fn from_stdin() -> Reader<'a> {
        Reader::Stdin(io::stdin().lock())
    }

    fn mut_ref(&mut self) -> &mut dyn BufRead {
        // Some type voodo are involved:
        // https://users.rust-lang.org/t/why-ref-mut-and-not-mut-in-enum-matching/95721/8
        match self {
            Reader::File(r) => r,
            Reader::Stdin(r) => r,
            Reader::Local(r) => r,
        }
    }
}

/// Implementation of a stream writer.
pub enum Writer<'a> {
    /// A file writer
    File(BufWriter<File>),
    /// A writer to stdout
    Stdout(StdoutLock<'a>),
    /// A writer to stderr
    Stderr(StderrLock<'a>),
    /// A writer to a local buffer
    Local(BufWriter<Vec<u8>>),
}

impl<'a> Writer<'a> {
    /// Create a writer from a file.
    pub fn to_file(file: File, buf_size: Option<usize>) -> Writer<'a> {
        match buf_size {
            Some(size) => Writer::File(BufWriter::with_capacity(size, file)),
            None => Writer::File(BufWriter::new(file)),
        }
    }

    /// Create a writer to the process' stdout.
    pub fn to_stdout() -> Writer<'a> {
        Writer::Stdout(io::stdout().lock())
    }

    /// Create a writer to the process' stderr.
    pub fn to_stderr() -> Writer<'a> {
        Writer::Stderr(io::stderr().lock())
    }

    fn mut_ref(&mut self) -> &mut dyn Write {
        // Some type voodo are involved:
        // https://users.rust-lang.org/t/why-ref-mut-and-not-mut-in-enum-matching/95721/8
        match self {
            Self::File(w) => w,
            Self::Stdout(w) => w,
            Self::Stderr(w) => w,
            Self::Local(w) => w,
        }
    }
}

/// The Carver struct is responsible for carving JSON strings out of the
/// provided reader, and provide output and reports to the provided writers.
pub struct Carver<'a> {
    jt: JsonTracker,
    reader: Reader<'a>,
    json_writer: Writer<'a>,
    report_writer: Writer<'a>,
    /// The minimum size of the JSON string that will be reported.
    pub min_size: usize,
    /// Whether to attempt to fix incomplete JSON strings.
    pub fix_incomplete: bool,
}

impl<'a> Carver<'a> {
    /// Create a new `Carver` instance from the provided `Reader` and `Writer`
    /// instances.
    pub fn new(
        reader: Reader<'a>,
        json_writer: Writer<'a>,
        report_writer: Writer<'a>,
        max_size: Option<usize>,
        max_ident_depth: Option<usize>,
    ) -> Self {
        Carver {
            jt: JsonTracker::new(max_size, max_ident_depth),
            reader: reader,
            json_writer: json_writer,
            report_writer: report_writer,
            min_size: DEFAULT_MIN_JSON_SIZE,
            fix_incomplete: false,
        }
    }

    /// Configure whether to replace newlines in JSON strings or not.
    pub fn replace_newlines(&mut self, opt: bool) {
        self.jt.replace_newlines = opt;
    }

    /// Basically skip_until(), if it could search for two bytes instead of
    /// one. Here, we mimic its behavior, using the memchr crate, since the
    /// internal memchr is not stable yet.
    ///
    /// The end product of this method is that the next read from the buffer
    /// should return the character we looked for.
    fn scout(&mut self) -> Result<Option<(usize, u8)>, io::Error> {
        let mut read = 0;
        let mut ch = 0;
        let r = self.reader.mut_ref();
        loop {
            let (done, used) = {
                let available = match r.fill_buf() {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                match memchr::memchr2(CHAR_LEFT_SQUARE_BRACKET, CHAR_LEFT_CURLY_BRACKET, available)
                {
                    Some(i) => {
                        // The only difference from skip_until is that we want
                        // to retain the last character.
                        ch = available[i];
                        (true, i + 1)
                    }
                    None => (false, available.len()),
                }
            };
            r.consume(used);
            read += used;
            if done {
                return Ok(Some((read, ch)));
            }
            if used == 0 {
                return Ok(None);
            }
        }
    }

    fn handle_left_square_bracket(&mut self) -> Result<Cause, io::Error> {
        self.jt.add_ident(CHAR_LEFT_SQUARE_BRACKET);
        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            match b {
                CHAR_LEFT_SQUARE_BRACKET
                | CHAR_LEFT_CURLY_BRACKET
                | CHAR_RIGHT_SQUARE_BRACKET
                | CHAR_QUOT_MARK
                | CHAR_MINUS
                | CHAR_ZERO..=CHAR_NINE
                | CHAR_START_FALSE
                | CHAR_START_NULL
                | CHAR_START_TRUE => return Ok(Cause::Found(b)),
                CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => self.jt.advance(b),
                _ => return Ok(Cause::Corrupted(b)),
            }
        }
        Ok(Cause::Exhausted)
    }

    fn handle_left_curly_bracket(&mut self) -> Result<Cause, io::Error> {
        self.jt.add_ident(CHAR_LEFT_CURLY_BRACKET);
        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            match b {
                CHAR_QUOT_MARK => {
                    self.jt.in_key = true;
                    return Ok(Cause::Found(b));
                }
                CHAR_RIGHT_CURLY_BRACKET => return Ok(Cause::Found(b)),
                CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => {
                    self.jt.advance(b);
                }
                _ => return Ok(Cause::Corrupted(b)),
            }
        }
        Ok(Cause::Exhausted)
    }

    fn handle_right_square_bracket(&mut self) -> Result<Cause, io::Error> {
        match self.jt.remove_ident(CHAR_LEFT_SQUARE_BRACKET) {
            Ok(true) => return Ok(Cause::Completed),
            Ok(false) => (),
            Err(_) => return Ok(Cause::Corrupted(CHAR_RIGHT_SQUARE_BRACKET)),
        }

        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            match b {
                CHAR_COMMA | CHAR_RIGHT_SQUARE_BRACKET | CHAR_RIGHT_CURLY_BRACKET => {
                    return Ok(Cause::Found(b))
                }
                CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => self.jt.advance(b),
                _ => return Ok(Cause::Corrupted(b)),
            }
        }
        Ok(Cause::Exhausted)
    }

    fn handle_right_curly_bracket(&mut self) -> Result<Cause, io::Error> {
        match self.jt.remove_ident(CHAR_LEFT_CURLY_BRACKET) {
            Ok(true) => return Ok(Cause::Completed),
            Ok(false) => (),
            Err(_) => return Ok(Cause::Corrupted(CHAR_RIGHT_CURLY_BRACKET)),
        }

        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            match b {
                CHAR_COMMA | CHAR_RIGHT_SQUARE_BRACKET | CHAR_RIGHT_CURLY_BRACKET => {
                    return Ok(Cause::Found(b))
                }
                CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => self.jt.advance(b),
                _ => return Ok(Cause::Corrupted(b)),
            }
        }
        Ok(Cause::Exhausted)
    }

    fn handle_colon(&mut self) -> Result<Cause, io::Error> {
        self.jt.in_key = false;
        self.jt.advance(CHAR_COLON);
        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            match b {
                CHAR_LEFT_CURLY_BRACKET
                | CHAR_LEFT_SQUARE_BRACKET
                | CHAR_MINUS
                | CHAR_ZERO..=CHAR_NINE
                | CHAR_QUOT_MARK
                | CHAR_START_FALSE
                | CHAR_START_NULL
                | CHAR_START_TRUE => return Ok(Cause::Found(b)),
                CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => self.jt.advance(b),
                _ => return Ok(Cause::Corrupted(b)),
            }
        }
        Ok(Cause::Exhausted)
    }

    fn handle_comma(&mut self) -> Result<Cause, io::Error> {
        self.jt.advance(CHAR_COMMA);
        match self.jt.last_ident() {
            Some(CHAR_LEFT_SQUARE_BRACKET) => {
                for b in self.reader.mut_ref().bytes() {
                    let b = b?;
                    match b {
                        CHAR_LEFT_CURLY_BRACKET
                        | CHAR_LEFT_SQUARE_BRACKET
                        | CHAR_MINUS
                        | CHAR_ZERO..=CHAR_NINE
                        | CHAR_QUOT_MARK
                        | CHAR_START_FALSE
                        | CHAR_START_NULL
                        | CHAR_START_TRUE => return Ok(Cause::Found(b)),
                        CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => {
                            self.jt.advance(b)
                        }
                        _ => return Ok(Cause::Corrupted(b)),
                    }
                }
                Ok(Cause::Exhausted)
            }
            Some(CHAR_LEFT_CURLY_BRACKET) => {
                for b in self.reader.mut_ref().bytes() {
                    let b = b?;
                    match b {
                        CHAR_QUOT_MARK => {
                            self.jt.in_key = true;
                            return Ok(Cause::Found(b));
                        }
                        CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => {
                            self.jt.advance(b)
                        }
                        _ => return Ok(Cause::Corrupted(b)),
                    }
                }
                Ok(Cause::Exhausted)
            }
            Some(_) => unreachable!(), // FIXME: Ensure that this is indeed unreachable.
            None => unreachable!(),    // FIXME: Ensure that this is indeed unreachable.
        }
    }

    fn handle_string(&mut self) -> Result<Cause, io::Error> {
        self.jt.advance(CHAR_QUOT_MARK);
        let mut in_string = true;
        let mut in_escape = false;
        let mut in_escaped_unicode = 0;

        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            let last_ident = self.jt.last_ident().unwrap();

            if !in_string {
                match (b, last_ident, self.jt.in_key) {
                    (CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN, _, _) => (),
                    // Case 1: A string value in a JSON list: ["test", "1"]
                    (CHAR_COMMA | CHAR_RIGHT_SQUARE_BRACKET, CHAR_LEFT_SQUARE_BRACKET, _) => {
                        return Ok(Cause::Found(b))
                    }
                    // Case 2: A value in a JSON object: {"test": "yes", "pain": "right"}
                    (CHAR_COMMA | CHAR_RIGHT_CURLY_BRACKET, CHAR_LEFT_CURLY_BRACKET, false) => {
                        return Ok(Cause::Found(b))
                    }
                    // Case 3: A key in a JSON object: {"test": 1, "pain": true}
                    (CHAR_COLON, CHAR_LEFT_CURLY_BRACKET, true) => return Ok(Cause::Found(b)),
                    (_, _, _) => return Ok(Cause::Corrupted(b)),
                }
            } else {
                match (b, in_escape, in_escaped_unicode) {
                    (CHAR_ESCAPE, false, 0) => in_escape = true,
                    (CHAR_QUOT_MARK, false, 0) => in_string = false,
                    (0x00..0x1F, _, _) => return Ok(Cause::Corrupted(b)),
                    (_, false, 0) => {
                        if byte_needs_escape(b) {
                            return Ok(Cause::Corrupted(b));
                        }
                    }
                    (CHAR_U, true, 0) => {
                        in_escaped_unicode = 4;
                        in_escape = false;
                    }
                    (_, true, 0) => {
                        if byte_can_escape(b) {
                            in_escape = false;
                        } else {
                            return Ok(Cause::Corrupted(b));
                        }
                    }
                    (_, _, 1..=4) => {
                        if b.is_ascii_hexdigit() {
                            in_escaped_unicode -= 1;
                        } else {
                            return Ok(Cause::Corrupted(b));
                        }
                    }
                    (_, _, _) => return Ok(Cause::Corrupted(b)),
                }
            }
            self.jt.advance(b);
        }
        Ok(Cause::Exhausted)
    }

    fn handle_number(&mut self, start_num: u8) -> Result<Cause, io::Error> {
        self.jt.advance(start_num);
        let mut in_frac = false;
        let mut in_exp = false;
        let mut in_leading_zero: Option<bool> = None;

        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            let last_byte = self.jt.last_byte().unwrap();

            // Check for leading zeroes.
            //
            // A leading zero can be preceeded by a minus sign (-), but cannot
            // be followed by digits.
            if in_leading_zero == None {
                in_leading_zero = match last_byte {
                    CHAR_MINUS => None,
                    CHAR_ZERO => Some(true),
                    _ => Some(false),
                }
            }
            if in_leading_zero == Some(true) {
                in_leading_zero = match b {
                    CHAR_ZERO..=CHAR_NINE => return Ok(Cause::Corrupted(b)),
                    _ => Some(false),
                }
            }

            match (last_byte, b) {
                // Only numbers can follow +/-/..
                (CHAR_MINUS | CHAR_PLUS | CHAR_DECIMAL, CHAR_ZERO..=CHAR_NINE) => (),
                // Only numbers or +/- can follow exponent signs.
                (
                    CHAR_EXP_LOWER | CHAR_EXP_UPPER,
                    CHAR_ZERO..=CHAR_NINE | CHAR_MINUS | CHAR_PLUS,
                ) => (),
                // Digits, insignificant whitespace, or ,]} can *always* follow
                // digits.
                (
                    CHAR_ZERO..=CHAR_NINE,
                    CHAR_ZERO..=CHAR_NINE | CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE,
                ) => (),
                // Decimal points can follow numbers if we're not in a
                // fractional/exponent part already.
                (CHAR_ZERO..=CHAR_NINE, CHAR_DECIMAL) => match (in_frac, in_exp) {
                    (true, _) | (_, true) => return Ok(Cause::Corrupted(b)),
                    (false, _) => in_frac = true,
                },
                // Exponent signs can follow numbers if we're not in a exponent
                // part already.
                (CHAR_ZERO..=CHAR_NINE, CHAR_EXP_LOWER | CHAR_EXP_UPPER) => match in_exp {
                    true => return Ok(Cause::Corrupted(b)),
                    false => in_exp = true,
                },
                // Numbers are complete only if digits and insignificant
                // whitespace are followed by ,]}.
                (
                    CHAR_SPACE
                    | CHAR_TAB
                    | CHAR_NEWLINE
                    | CHAR_CARRIAGE_RETURN
                    | CHAR_ZERO..=CHAR_NINE,
                    CHAR_COMMA | CHAR_RIGHT_SQUARE_BRACKET | CHAR_RIGHT_CURLY_BRACKET,
                ) => return Ok(Cause::Found(b)),
                // Everything else is not permitted.
                (_, _) => return Ok(Cause::Corrupted(b)),
            }
            self.jt.advance(b);
        }
        Ok(Cause::Exhausted)
    }

    fn handle_literal(&mut self, start_char: u8) -> Result<Cause, io::Error> {
        self.jt.advance(start_char);
        let literal: &[u8] = match start_char {
            CHAR_START_FALSE => "alse".as_bytes(),
            CHAR_START_NULL => "ull".as_bytes(),
            CHAR_START_TRUE => "rue".as_bytes(),
            _ => unreachable!(),
        };

        for (i, b) in self.reader.mut_ref().bytes().enumerate() {
            let b = b?;
            if literal[i] != b {
                return Ok(Cause::Corrupted(b));
            }
            self.jt.advance(b);
            if literal.len() == i + 1 {
                break;
            }
        }

        for b in self.reader.mut_ref().bytes() {
            let b = b?;
            match b {
                CHAR_COMMA | CHAR_RIGHT_SQUARE_BRACKET | CHAR_RIGHT_CURLY_BRACKET => {
                    return Ok(Cause::Found(b));
                }
                CHAR_SPACE | CHAR_TAB | CHAR_NEWLINE | CHAR_CARRIAGE_RETURN => self.jt.advance(b),
                _ => return Ok(Cause::Corrupted(b)),
            }
        }
        Ok(Cause::Exhausted)
    }

    fn hunt(&mut self, mut ch: u8) -> Result<Cause, ()> {
        loop {
            let res = match ch {
                CHAR_LEFT_SQUARE_BRACKET => self.handle_left_square_bracket(),
                CHAR_LEFT_CURLY_BRACKET => self.handle_left_curly_bracket(),
                CHAR_RIGHT_SQUARE_BRACKET => self.handle_right_square_bracket(),
                CHAR_RIGHT_CURLY_BRACKET => self.handle_right_curly_bracket(),
                CHAR_COLON => self.handle_colon(),
                CHAR_COMMA => self.handle_comma(),
                CHAR_QUOT_MARK => self.handle_string(),
                CHAR_MINUS | CHAR_ZERO..=CHAR_NINE => self.handle_number(ch),
                CHAR_START_FALSE | CHAR_START_NULL | CHAR_START_TRUE => self.handle_literal(ch),
                _ => {
                    return Err(());
                }
            };

            ch = match res {
                Ok(Cause::Completed) => {
                    return Ok(Cause::Completed);
                }
                Ok(Cause::Found(ch)) => ch,
                Ok(Cause::Corrupted(ch)) => {
                    return Ok(Cause::Corrupted(ch));
                }
                Ok(Cause::Exhausted) => {
                    return Ok(Cause::Exhausted);
                }
                Err(_) => {
                    return Err(()); // FIXME: Capture this error
                }
            }
        }
    }

    fn _print_incomplete(&mut self) {
        let w = self.json_writer.mut_ref();
        w.write_all(&self.jt.processed[..self.jt.partial_close_end + 1])
            .unwrap();
        for i in (0..self.jt.cur_ident_level).rev() {
            let closing_ident = _closing_ident(self.jt.ident_levels[i]);
            w.write_all(&[closing_ident]).unwrap();
        }
        w.write_all(&[CHAR_NEWLINE]).unwrap();
    }

    /// Start carving a stream of data for JSON strings.
    pub fn parse(&mut self) -> () {
        let mut start = 0;
        let mut lastb: Option<u8> = None;

        loop {
            let (read, ch) = match lastb {
                Some(CHAR_LEFT_CURLY_BRACKET) | Some(CHAR_LEFT_SQUARE_BRACKET) => {
                    (0, lastb.unwrap())
                }
                _ => match self.scout() {
                    Ok(None) => {
                        break;
                    }
                    Ok(Some((read, ch))) => (read, ch),
                    Err(_) => {
                        break;
                    }
                },
            };
            start = start + read - 1;
            if lastb.is_some() {
                start += 1;
            }

            match self.hunt(ch) {
                Ok(Cause::Completed) => {
                    let end = start + self.jt.cur - 1;
                    let w = self.json_writer.mut_ref();
                    if self.jt.cur >= self.min_size {
                        w.write_all(&self.jt.processed[..self.jt.cur]).unwrap();
                        w.write_all(&[CHAR_NEWLINE]).unwrap();
                    }
                    start = end + 1;
                    lastb = None;
                }
                Ok(Cause::Corrupted(ch)) => {
                    let corrupted_end = start + self.jt.cur - 1;
                    let partial_end = start + self.jt.partial_close_end;
                    if self.jt.partial_close_end >= self.min_size {
                        let report = Report {
                            status: Cause::Corrupted(ch),
                            start: start,
                            end: corrupted_end,
                            partial_end: partial_end,
                        };
                        report.print(&mut self.report_writer);
                        if self.fix_incomplete {
                            self._print_incomplete()
                        }
                    }
                    start = corrupted_end + 1;
                    lastb = Some(ch);
                }
                Ok(Cause::Exhausted) => {
                    let corrupted_end = start + self.jt.cur - 1;
                    let partial_end = start + self.jt.partial_close_end;
                    if self.jt.partial_close_end >= self.min_size {
                        let report = Report {
                            status: Cause::Exhausted,
                            start: start,
                            end: corrupted_end,
                            partial_end: partial_end,
                        };
                        report.print(&mut self.report_writer);
                        if self.fix_incomplete {
                            self._print_incomplete()
                        }
                    }
                    break;
                }
                Ok(Cause::Found(_)) => unreachable!(),
                Err(_) => {
                    break;
                }
            };
            self.jt.quick_clean();
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn create_carver<'a>(buf: &'a [u8]) -> Carver<'a> {
        let reader = BufReader::new(buf);
        let json_writer = BufWriter::new(vec![]);
        let report_writer = BufWriter::new(vec![]);
        let mut carver = Carver::new(
            Reader::Local(reader),
            Writer::Local(json_writer),
            Writer::Local(report_writer),
            None,
            None,
        );
        carver.min_size = 0;
        carver
    }

    fn get_buf(writer: &Writer) -> Vec<u8> {
        let mut res_buf = match writer {
            Writer::Local(w) => w.buffer().to_vec(),
            _ => unreachable!(),
        };
        if res_buf.last() == Some(&CHAR_NEWLINE) {
            res_buf.pop();
        }
        res_buf
    }

    /// Parse buffer and return the string that is printed.
    fn parse(buf: &[u8]) -> Vec<u8> {
        let buf_disp = String::from_utf8_lossy(buf);
        eprintln!("### Evaluating buffer: {buf_disp}");
        let mut carver = create_carver(buf);
        carver.parse();
        let res_buf = get_buf(&carver.json_writer);
        let res_buf_disp = String::from_utf8_lossy(&res_buf);
        eprintln!("### Result is: {res_buf_disp}");
        res_buf
    }

    fn report_incomplete(buf: &[u8], fix: bool) -> (Vec<u8>, Vec<u8>) {
        let buf_disp = String::from_utf8_lossy(buf);
        eprintln!("### Evaluating buffer: {buf_disp}");
        let mut carver = create_carver(buf);
        carver.fix_incomplete = fix;
        carver.parse();
        let json_buf = get_buf(&carver.json_writer);
        let report_buf = get_buf(&carver.report_writer);
        let json_buf_disp = String::from_utf8_lossy(&json_buf);
        let report_buf_disp = String::from_utf8_lossy(&report_buf);
        eprintln!("### Result is: {json_buf_disp}");
        eprintln!("### Report is: {report_buf_disp}");
        (json_buf, report_buf)
    }

    /// Parse buffer and return a list of strings that are printed, delimited
    /// by newlines.
    fn collect(buf: &[u8]) -> Vec<String> {
        let buf: Vec<u8> = parse(buf);
        let s: String = String::from_utf8(buf)
            .unwrap()
            .trim_end_matches("\n")
            .to_string();
        let mut v: Vec<String> = vec![];
        for line in s.lines() {
            v.push(line.to_owned())
        }
        v
    }

    #[test]
    fn test_parse_found() {
        let buf = "{}";
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = "[{}]";
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = "{ {} ]";
        assert_eq!(collect(buf.as_bytes()), ["{}"]);
        let buf = "{    []";
        assert_eq!(collect(buf.as_bytes()), ["[]"]);
        let buf = "hey\n{[]}";
        assert_eq!(collect(buf.as_bytes()), ["[]"]);
        let buf = "hey";
        assert_eq!(collect(buf.as_bytes()), vec![] as Vec<String>);
        let buf = "[[[[[[[{}]]]]]]]";
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = "I[{}]want[[]]moar";
        assert_eq!(collect(buf.as_bytes()), ["[{}]", "[[]]"]);
        let buf = r#"{"hey": "there"}"#;
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = r#"{"hey": "there"}{"how": "are", "you": "doing?"}"#;
        assert_eq!(
            collect(buf.as_bytes()),
            [r#"{"hey": "there"}"#, r#"{"how": "are", "you": "doing?"}"#,]
        );
        let buf = r#"["test", ["nested", {"json": "objs"}]]"#;
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = r#"[1, 2]"#;
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = r#"[1, {"test": -2}]"#;
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = r#"[1]{[-9]test: 9}"#;
        assert_eq!(collect(buf.as_bytes()), ["[1]", "[-9]"]);
        let buf = r#"{"numbers": 9, "literals": true, "lists": ["1", false, {}]}"#;
        assert_eq!(collect(buf.as_bytes()), [buf]);
        let buf = r#"[trap, [nullify, 1], {"true": true}]"#;
        assert_eq!(collect(buf.as_bytes()), [r#"{"true": true}"#]);
        let buf = r#"[1]{"key":"val":  [2],[fal[3]]]"#;
        assert_eq!(collect(buf.as_bytes()), ["[1]", "[2]", "[3]"]);
    }

    #[test]
    fn test_parse_fail() {
        let bad_buffers: Vec<&str> = vec![
            "hey",
            r#"{"hey", "there"}"#,
            "{:}",
            "{]}",
            r#"{9: "9"}"#,
            r#"{"more": "colons": "bad"}"#,
            r#"{"test":, "bad"}"#,
            r#"[:]"#,
            r#"["a", "b",]"#,
            r#"["a", "b", {": "test"}]"#,
            "999",
            r#"{999: "666"}"#,
            r#"[999: "666"]"#,
            r#"[999   , ]"#,
            r#"[trap]"#,
            r#"[nullify]"#,
            r#"{true: false}"#,
            r#"[true"#,
            r#"[false"#,
            r#"[null"#,
            r#"[9"#,
            r#"["test"#,
            r#"["test""#,
            "[{",
            "[",
            "{",
        ];
        for buf in bad_buffers {
            assert_eq!(collect(buf.as_bytes()), vec![] as Vec<String>);
        }
    }

    #[test]
    fn test_report_incomplete() {
        let buf = "{";
        let buf_expected = "{}";
        let report_expected = "exhausted,0,0,0";
        let (buf, report) = report_incomplete(buf.as_bytes(), true);
        assert_eq!(buf, buf_expected.as_bytes());
        assert_eq!(report, report_expected.as_bytes());

        let buf = "[{[{[[";
        let buf_expected = "[{}]\n\
                            [{}]\n\
                            [[]]";
        let report_expected = "corrupted,0,1,1\n\
                               corrupted,2,3,3\n\
                               exhausted,4,5,5";
        let (buf, report) = report_incomplete(buf.as_bytes(), true);
        assert_eq!(buf, buf_expected.as_bytes());
        assert_eq!(report, report_expected.as_bytes());

        let buf = r#"{"test": {"inside": [1, 2]"#;
        let buf_expected = r#"{"test": {"inside": [1, 2]}}"#;
        let report_expected = "exhausted,0,25,25";
        let (buf, report) = report_incomplete(buf.as_bytes(), true);
        assert_eq!(buf, buf_expected.as_bytes());
        assert_eq!(report, report_expected.as_bytes());

        let buf = r#"[1, 2, 3, {"test"[true, null, far{"key": "value",[9]"#;
        let buf_expected = "[1, 2, 3, {}]\n\
                            []\n\
                            {}\n\
                            [9]";
        let report_expected = "corrupted,0,16,10\n\
                               corrupted,17,31,17\n\
                               corrupted,33,48,33";
        let (buf, report) = report_incomplete(buf.as_bytes(), true);
        assert_eq!(buf, buf_expected.as_bytes());
        assert_eq!(report, report_expected.as_bytes());

        let buf = r#"[1]{"key":"val":  [2],[fal[3]]]"#;
        let buf_expected = "[1]\n\
                            {}\n\
                            [2]\n\
                            []\n\
                            [3]";
        let report_expected = "corrupted,3,14,3\n\
                               corrupted,22,25,22";
        let (buf, report) = report_incomplete(buf.as_bytes(), true);
        assert_eq!(buf, buf_expected.as_bytes());
        assert_eq!(report, report_expected.as_bytes());
    }
}
