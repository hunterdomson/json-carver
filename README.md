# JSON carver

JSON carver is a tool that can extract JSON strings from any byte stream. In
digital forensics, this is a process known as "data carving".

It was written so that the [Reporters United](https://reportersunited.gr/en)
team could recover text messages with Greek characters from the [Telemessage
heap dumps](https://ddosecrets.com/article/telemessage). The original method to
filter through this dataset was to use the trusty `strings(1)` utility, which
by default filters only ASCII characters, meaning that messages in non-English
languages or messages that contained emojis would be discarded.

## Features

* **Faster than the `strings(1)` utility**

  JSON carver only looks for characters that start with `[` or `{`, so it can
  skim through large dumps of binary data using AVX2 instructions in CPUs that
  support them (see [`memchr`](https://github.com/BurntSushi/memchr)).

* **Full Unicode support**

  JSON carver can detect JSON strings that contain any supported Unicode character
  as well as escaped Unicode sequences.

* **Compliant with [RFC-8259](https://www.rfc-editor.org/rfc/rfc8259)**

   JSON carver prints only structurally valid JSON strings that are safe to be
   ingested by other tools.

* **JSONL support**

  JSON carver can convert multi-line JSON strings into a single line, so that
  they can be processed by other line-oriented tools.

* **Detects corrupted strings**

  JSON carver can detect corrupted strings in a byte stream, and report their
  positions to their user for further inspection. Optionally, it can attempt to
  partially reconstruct them.

* **Tested against [JSONTestSuite](https://github.com/nst/JSONTestSuite)**

## Installation

```
cargo install json-carver
```

## Examples

List of options that `json-carver` supports:

```
$ json-carver --help
Find JSON strings in a file faster than strings(1), print structurally valid ones and report corrupted ones

Usage: json-carver [OPTIONS]

Options:
  -i, --input <INPUT>        File to carve. Reads from stdin by default
  -o, --output <OUTPUT>      Where to write the JSON strings. Writes to stdout by default
  -r, --report <REPORT>      Where to write the report for corrupted strings. Writes to stderr by default
      --replace-newlines     Replace newlines in JSON strings with a space (" ") character
      --min-size <MIN_SIZE>  Minimum size of JSON strings to report [default: 4]
      --fix-incomplete       Attempt to fix incomplete JSON strings by returning an incomplete, but structurally valid, version of them
      --report-all           Report every JSON string in the stream, not just corrupted ones
  -h, --help                 Print help
  -V, --version              Print version
```

### Example 1: Filter JSON strings

We'll show how `json-carver` works, against a file with JSON strings
interspersed with other data. Here's an example file:

```
$ cat > bytes <<EOF
oh look, JSON strings! [1,2]0000[3,4]
and a larger one ["test", null, 1]0000000000000000000
and one with newlines
{
  "long": "json"
}}}}}}}}
EOF
```

First, let's filter the JSON strings in this byte stream:

```
$ json-carver -i bytes
[1,2]
[3,4]
["test", null, 1]
{
  "long": "json"
}
```

Exclude the small ones with `--min-size`:

```
$ json-carver -i bytes --min-size 9
["test", null, 1]
{
  "long": "json"
}
```

Make the multi-line JSON string fit into a single line with `--replace-newlines`:

```
$ json-carver -i bytes --min-size 9 --replace-newlines
["test", null, 1]
{   "long": "json"  }
```

### Example 2: Report corrupted strings

Report JSON strings that are corrupted or incomplete:

```
$ echo '{"valid": [1,2], "nope00000' | json-carver
corrupted,0,26,14
```

Reports have four fields:
* status ("corrupted")
* start position in the stream (0)
* end position in the stream (26)
* last position where the string could be partially recovered (14)

Attempt to partially recover this string:

```
$ echo '{"valid": [1,2], "nope00000' | json-carver --fix-incomplete
corrupted,0,26,14
{"valid": [1,2]}
```

## License

JSON carver is licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in assets by you, as defined in the Apache-2.0 license, shall be
dually licensed as above, without any additional terms or conditions.
