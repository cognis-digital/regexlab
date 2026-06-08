# Demo 01 - Basic triage of an app log

A developer pasted a chunk of an application log + config dump (`app_dump.log`)
into a ticket. Before sharing it further you want to know whether it leaks any
secrets or PII, understand a tricky regex a teammate wrote, and confirm that
regex isn't a ReDoS footgun.

## 1. Scan the artifact for secrets / PII

```
python -m regexlab scan -i demos/01-basic/app_dump.log
```

Exit code is non-zero because findings exist (good for CI gating). Findings are
redacted in output so the report itself doesn't leak the full secret.

Produce a shareable HTML report (the UI):

```
python -m regexlab scan -i demos/01-basic/app_dump.log --format html -o scan.html
```

Machine-readable for a pipeline:

```
python -m regexlab scan -i demos/01-basic/app_dump.log --format json
```

## 2. Explain a teammate's regex

```
python -m regexlab explain "\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
```

## 3. Test + ReDoS-check a regex

```
python -m regexlab test "(a+)+$" -t "aaaaaaaaaaaaaaaaX"
```

The `redos risk: high` line warns you the pattern can catastrophically
backtrack before you ship it.

## 4. Benchmark

```
python -m regexlab bench "\d{3}-\d{4}" -i demos/01-basic/app_dump.log --iterations 2000
```
