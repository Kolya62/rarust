# Development tools

Generators of valid packed streams with random content, for testing the
decoders without RAR. They only produce raw compressed data, not archives.

- `gen_rar2_stream.py SEED FILES` and `gen_rar3_stream.py SEED FILES`
  write frames for `examples/unpack_stream.rs` (methods 20 and 29): all
  symbol kinds, table updates, audio blocks (RAR 2.x), filter definitions
  (RAR 3.x) and solid continuation over several files.
- `gen_rar5_stream.py SIZE SEED OUT` writes a RAR 5.0 block stream and
  the expected output to `OUT.plain`.

Compare two builds of the decoder:

```bash
python3 tools/gen_rar3_stream.py 1 4 > s.bin
cargo run --release --example unpack_stream -- 29 < s.bin | md5sum
```
