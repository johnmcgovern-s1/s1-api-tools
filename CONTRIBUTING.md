# Contributing

## The rules

1. **Pure Python 3 standard library.** No `pip install`, no `requirements.txt`.
   Use `urllib.request`, not `requests`. A tool must run on a stock Python 3 —
   including the macOS system Python (**3.9**) — because these get copied to jump
   hosts and handed to customers.
   - 3.9 gotcha: `datetime.fromisoformat` won't parse a trailing `Z` before 3.11;
     strip it yourself.
2. **One directory per tool**, kebab-case, with a README beside the code:
   ```
   tools/<tool-name>/
     README.md
     <tool_name>.py
   ```
   Snake_case the module, kebab-case the directory. A tool should be a **single
   file** where practical, so it can be copied on its own.
3. **Tokens come from the environment**, never a file in the repo and never a
   default in the code. Accept `--token` as an override but document the env var
   (`S1_SDL_TOKEN` for Data Lake) as the preferred path.
4. **Write output to `reports/<tool>/` by default**, resolved from the tool's own
   location (`__file__`), *not* the current directory — a cwd-relative default
   scatters customer data wherever the operator happened to be standing. Fall
   back to a cwd-relative path when the file has been copied out of the repo.
   Print the resolved absolute path on every run. Accept `--out-dir` to override.
5. **Never commit tool output.** It contains customer data. `reports/` is already
   ignored; add any new output pattern to `.gitignore`.
   - Anchor directory patterns to the root (`/out/`, not `out/`) and never use
     unanchored globs like `*-report/` — that also matches tool directories such
     as `tools/sdl-k8s-process-report/` and silently ignores the code.
6. **Add the tool to the table in [README.md](README.md).**

## What a good tool does

These are field tools — someone runs one under time pressure against a
customer's live tenant. That shapes the requirements:

- **`--dry-run`.** Show what would be sent and how the work will be chunked,
  without calling the API.
- **Surface the API's error body on the first failure.** A status code alone is
  useless. Never swallow the response body in a retry path — a malformed-query
  500 will never succeed on retry, and the operator needs the reason immediately.
- **Retry only what's retryable**, with backoff, honouring `Retry-After`.
- **Never present partial results as complete.** If data was dropped, say so on
  stderr, say how much, and say which flag fixes it. This matters more than it
  sounds: see the `omittedEvents` note in [README.md](README.md).
- **Checkpoint long runs** so an interrupt resumes instead of restarting, and
  handle `KeyboardInterrupt` without a traceback.
- **Stream output** rather than buffering a whole result set in memory.
- **Validate arguments up front** with actionable messages — an empty time
  window, a floor above a ceiling, a missing token.

## Testing

There's no CI: these tools need a live tenant and a token, which CI doesn't have.
So test by **monkeypatching the request function** and driving the logic with
synthetic responses — that covers the parts that actually break (pagination,
joins, truncation handling, resume) without a network call. Keep such tests
outside the repo unless they're worth committing; if you commit them, put them in
`tools/<tool-name>/tests/` and keep them stdlib-only too.

Before you hand a tool to anyone, run it against a real tenant with a **short
time window** and read the output. Mock tests prove the logic, not that the query
is accepted.

## Documenting API surprises

When you discover an undocumented API constraint, **write it down in the tool's
README and in the root [README.md](README.md)** if it generalises. The three
PowerQuery constraints in the root README each cost real debugging time; the
point of this repo is that nobody pays that twice.
