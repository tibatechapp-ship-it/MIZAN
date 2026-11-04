# MIZAN — Free and Open Source Policy

## 1. Project Commitment

MIZAN is a free and open-source software analysis,
testing, and verification engine.

The core project will not require:
- Paid subscriptions
- Mandatory payment
- Paid activation keys
- Locked essential features

## 2. License

The project is intended to use the MIT License.

## 3. Privacy by Design

MIZAN is designed to analyze repositories inside
the execution environment chosen by the user.

MIZAN must not upload repository source files,
private project files, or analysis contents to
MIZAN-controlled servers.

Local execution is the default privacy-oriented model.

## 4. Execution Environments

MIZAN aims to support:

- Local execution on Android using Termux
- Windows
- Linux
- GitHub integration
- GitLab integration
- Customer-managed self-hosted runners

Cloud-hosted CI runners are controlled by their
respective providers and are not equivalent to
fully local execution.

## 5. External Tools

MIZAN may integrate with free and open-source
third-party analysis tools.

Each integration must document:

- Its license
- Installation requirements
- Network requirements
- Data access
- Any usage limits or external costs

MIZAN must not claim that third-party services
are free without limits.

## 6. Security Defaults

The default analysis mode must be read-only.

MIZAN must not execute untrusted repository code
during static analysis.

Any operation that modifies files or executes
project code must require an explicit user decision.

## 7. Platform Support

The project aims to support GitHub and GitLab,
including repository analysis and CI workflows.

Platform-specific limits and charges remain
subject to each platform's own policies.

## 8. Community

The project welcomes contributions, integrations,
bug reports, and improvements from the community.

Essential core functionality must remain available
without mandatory payment.
