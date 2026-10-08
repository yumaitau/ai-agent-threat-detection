# Contributing

Start with an issue describing the detection, false positive or bug. Include the platform, detection ID, expected result and a sanitised example. Do not attach real tenant logs, credentials, personal details or private endpoints.

Keep changes within the relevant platform folder. Preserve detection IDs and existing source mappings. New mappings need a source and an explanation of the relationship; a detection is not proof that a control is met.

For a detection change, describe the log prerequisites, time window, threshold, expected false positives and validation status. Add a small synthetic positive and negative example where the existing validator supports it. Mark assumptions about fields, values or event shapes in the file header. Report live testing separately from offline checks.

For playbook changes, describe permissions, approval, expiry and recovery. Test changes to approval or containment logic with stubs before trying them in a lab.

Run `bash tools/validate_all.sh` using the [validation setup](docs/validation.md#run-locally). Keep the pinned dependency and provider lock files. If the combined CSV changes, regenerate its table with `python3 tools/build_mappings.py`.

Open a pull request with the problem, change, validation results and remaining limits. Use plain Australian English in docs, preserve API identifiers, and avoid em dashes. Add the change to [CHANGELOG.md](CHANGELOG.md). Contributions are licensed under the project's MIT licence and follow the [code of conduct](CODE_OF_CONDUCT.md).
