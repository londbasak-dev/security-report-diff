# Security policy

This project is an offline review aid, not a security certification. Use only
artifacts you are authorized to inspect. Keep original inputs and generated
reports private; selected identifiers or paths can themselves be sensitive.

Do not post credentials, real customer data, real scanner reports or APKs in
public issues. For a suspected vulnerability, share a minimal synthetic
reproducer through the repository host's private vulnerability reporting
feature if enabled. If no private channel is configured, first ask maintainers
for one using a public issue without exploit details or sensitive attachments.
No response-time or support guarantee is implied.

Only the current development version is in scope for fixes. The CLI does not
make network calls or upload inputs. Review third-party tools separately and
isolate hostile artifacts. Ignore rules reduce accidents but are not a secret
scanner; inspect staged files before any publication.
