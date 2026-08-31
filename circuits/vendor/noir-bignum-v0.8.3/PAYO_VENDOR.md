# PAYO vendoring record

- Upstream: `https://github.com/noir-lang/noir-bignum`
- Tag: `v0.8.3`
- Commit: `dd2070f`
- License: MIT; see `LICENSE` in this directory.
- Local change: `runtime_bignum` is public so PAYO can use the upstream
  `evaluate_quadratic_expression` helper with runtime Stark-field parameters.

The source is vendored to keep proof builds deterministic and to avoid copying
the library's arithmetic constraints into PAYO. No arithmetic implementation
was changed.
