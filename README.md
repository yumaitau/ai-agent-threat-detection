# AI and agent threat detection

A free, open-source toolkit for finding signs of risky AI activity in Microsoft, AWS and Google systems. It gives IT and security teams checks to run, response workflows to adapt, and records of which AI agents have access to what.

An **AI agent** is software that can take actions on someone's behalf, such as reading files, sending messages or using other tools.

**An IT or security team needs to set this up.** They will need access to your cloud services, activity records and security settings. Start in a separate test environment before using it in everyday operations.

## Validation status: checked offline, not tested live

**All implemented files passed the supplied offline syntax, schema or structural checks for their format. They have NOT been tested against live tenants, cloud accounts, organisations or Google Security Operations instances. Thresholds need tuning.**

In plain language, automated checks have examined the code's structure and expected data fields. We have not yet proved that it detects attacks or that its response workflows work in a real organisation.

A **threshold** is the point at which a check raises an alert, such as an unusually large number of file downloads. Your team must adjust these settings to suit normal activity in your environment. An alert on harmless activity is a **false positive**.

Some checks are draft investigations or written specifications rather than ready-to-run rules. The [validation guide](docs/validation.md) explains exactly what was checked, the warnings and the remaining gaps.

## What does it look for?

| Risk | Example of activity to investigate |
|---|---|
| Unapproved AI use, sometimes called **shadow AI** | A program on a work computer contacting an AI service that your organisation has not approved. |
| Rogue agents or agents with too much access | An unregistered agent appearing, or an AI app receiving permission to read more files or messages than it needs. |
| Misuse of agent credentials | An agent's login details or access keys being used from an unexpected location, or an agent relying on long-lived keys. |
| Malicious instructions followed by possible data theft | An AI security service flags a **prompt injection**, an attempt to make AI follow an attacker's instructions, followed by unusual data access or transfer. |
| Rapid bot activity or attacks on public websites | Many requests probing a website for weaknesses or trying to reach AI tool endpoints in a short time. |

These are signals for investigation. A high request rate alone does not prove that an attacker used AI. The prompt-injection checks use signals from existing security services and look for suspicious activity afterwards.

## How it works

1. **Your cloud services record activity.** These records, called logs, might show a login, a permission change or a file download. Your team enables the logs each check needs.
2. **The detection rules look for patterns.** When configured to run, they identify activity that needs investigation.
3. **Your team investigates and chooses a response.** The supplied playbooks describe response steps and include templates for automating some of them.
4. **The register and reports keep a record.** They track agent ownership, access, approval decisions and reviews.

The pack runs in your own cloud environment. Some response workflows can disable accounts or block traffic. Your team must review their permissions and approval settings before enabling them.

## What is included?

- **Detection rules and draft investigations:** checks for suspicious activity, with notes about the data they need and known limits.
- **Response playbooks:** instructions and automation templates for investigating, containing or reviewing an agent.
- **An AI agent register:** a list of agents, their owners, purposes, permissions and review decisions.
- **Reports and security mappings:** exports and tables to support a security review or assessment.

There are **45 named detection entries across three platforms**. Some have several technical formats; others are drafts or specifications. This is not a claim that 45 rules have been proven in live use.

## Choose your platform

You can use one pack on its own. You do not need all three platforms.

| Platform | What the pack covers | Setup guide |
|---|---|---|
| Microsoft | AI and agent activity recorded by Microsoft Sentinel, Defender XDR and related services, including identity, file access and website traffic. Includes a register and dashboard. | [Microsoft guide](microsoft/README.md) |
| AWS, Amazon Web Services | AI workloads, agent permissions, model use and website attacks recorded by AWS services. Includes a register, response workflows and evidence exports. | [AWS guide](aws/README.md) |
| Google Cloud and Google Workspace | AI apps, agent permissions, Workspace activity and website attacks. Includes a register and response workflows. Google Security Operations is optional. | [Google guide](google/README.md) |

Each guide lists the services, permissions and activity records required. Some features need particular subscriptions or extra logging. Cloud providers may charge for logging, storage and queries.

## Where should I start?

**If you manage the business, risk or compliance:** choose the platform your organisation uses and share its setup guide with your IT or security team. Agree which risks to investigate first and who will own the agent register. Ask for test results before enabling it in everyday operations.

**If you are setting it up:** read the platform guide and [validation limits](docs/validation.md), then use the quick start below. Each pack needs configuration and testing. Some response steps and dashboards are still designs rather than complete implementations.

## Quick start for the team setting this up

Download or clone this repository, then follow the [offline validation setup](docs/validation.md#run-locally). Work in a separate test environment and replace the example identifiers with your own configuration.

### Microsoft

1. Follow the [Microsoft guide](microsoft/README.md) to enable the required Sentinel and Defender data sources.
2. From `microsoft/`, install the register using `deploy/register-infra.json`, then the workbook dashboard and selected analytics rule templates.
3. Configure the playbook identities and connections. Rules and Logic Apps start disabled. Test with representative events, adjust thresholds and check approval and recovery before enabling them.

### AWS

1. Follow the [AWS guide](aws/README.md) to configure the activity logging needed for your chosen checks.
2. From `aws/`, run `python3 tools/package_lambdas.py`. Upload the generated files to your storage bucket, then deploy `deploy/cfn/yuma-aia-core.yaml` in a test account.
3. Review the website-blocking workflow in `deploy/terraform/pb3-waf-block/` with `auto_block = false`. Populate the register and test approvals. The component that runs the SQL detections on a schedule is not included yet.

### Google

1. Follow the [Google guide](google/README.md) to configure Cloud logging and the Workspace activity export.
2. In `google/deploy/terraform/`, copy `terraform.tfvars.example` to `terraform.tfvars`, replace every placeholder, then run `terraform init` and `terraform plan`. Review the proposed changes before applying them in a test environment.
3. Configure the approval service and Workspace permissions, populate the register and test each playbook. If using Google Security Operations, also configure its reference lists and compile the supplied detection rules there.

## How do the security mappings help?

The [combined table](mappings/README.md) and [downloadable CSV](mappings/detections.csv) connect each detection to the security controls or threat categories recorded in its source pack. They cover Australia's Information Security Manual (ISM) and Essential Eight, plus the MITRE ATLAS, ATT&CK and OWASP threat frameworks.

These mappings help a security team organise a review. They do not certify compliance or show that a control has been met. The register and exported reports are evidence to assess alongside your organisation's policies and practices.

## Help, contributions and security

Use the repository's issue templates to report a bug, suggest a detection or describe a false positive. Remove private information from examples. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

For changes, read [CONTRIBUTING.md](CONTRIBUTING.md). Participation follows the [Contributor Covenant](CODE_OF_CONDUCT.md). The [folder guide](docs/layout.md) explains where to find each part of the project.

## Licence

The code is available under the MIT licence, which allows use, modification and sharing subject to its terms. Copyright 2026 Yuma IT Pty Ltd. See [LICENSE](LICENSE). The Contributor Covenant retains its attribution in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
