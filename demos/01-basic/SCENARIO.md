# Demo 01 - Basic Wayback recon

## Scenario

You are reviewing the **historical attack surface** of a domain you own,
`example.com`. You pulled an archived-URL export from the Wayback Machine's CDX
API (the kind of file `waybackurls` / `gau` produce) and saved it as
`wayback_export.txt`. Before a re-test, you want to triage which of these old,
indexed endpoints are interesting: leaked secrets, backup files, config files,
admin panels, and parameters historically associated with vuln classes
(open-redirect, LFI, SSRF, SQLi, IDOR).

This is **defensive** analysis over an artifact you are authorized to review.
WAYBACKRECON never touches the network and never tests any endpoint -- it only
parses and classifies the export.

## Input

`wayback_export.txt` mixes two real formats on purpose:

* CDX server rows (`urlkey timestamp original mimetype statuscode ...`)
* plain one-URL-per-line entries

## Run it

```bash
# Human-readable table
python -m waybackrecon scan demos/01-basic/wayback_export.txt

# Machine-readable for pipelines
python -m waybackrecon scan demos/01-basic/wayback_export.txt --format json

# Shareable self-contained HTML report (the "UI")
python -m waybackrecon scan demos/01-basic/wayback_export.txt --format html -o report.html

# Only show the serious stuff
python -m waybackrecon scan demos/01-basic/wayback_export.txt --min-severity high
```

## Expected

* A **critical** finding for the API key leaked in a query string and for the
  exposed `.htpasswd`.
* **High** findings for the `.env`, `.git/config`, `phpinfo`, and `db.sql.bak`
  backup/config/debug endpoints.
* **Medium/low** findings for the admin panel, login endpoint, and the
  `redirect=`, `file=`, and `id=` parameters.
* Exit code `1` (medium+ findings present) or `2` if the input had parse errors.
