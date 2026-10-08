#!/usr/bin/env python3
"""Builds dist/ for upload to the artifact bucket: dist/lambda/<module>.zip and dist/asl/PB1-agent-containment.asl.json.
Then: aws s3 sync dist/ s3://<ArtifactBucket>/<ArtifactPrefix>
Bundle a current boto3 (pip install boto3 -t build/) if the Lambda runtime's boto3 lacks bedrock-agentcore-control or
agent-registry-control; this script copies build/ into each zip when it exists."""
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
LAMBDA = ROOT / "playbooks" / "lambda"
DIST = ROOT / "dist"
EXTRA = {"pb3_waf_block": [ROOT / "detections" / "A14-ai-speed-waf-burst.logsinsights"],
         "pb5_evidence_export": [ROOT / "register" / "ism-control-map.csv"]}


def main():
    shutil.rmtree(DIST, ignore_errors=True)
    (DIST / "lambda").mkdir(parents=True)
    (DIST / "asl").mkdir(parents=True)
    vendored = ROOT / "build"
    for mod in sorted(p.stem for p in LAMBDA.glob("pb*.py")):
        with zipfile.ZipFile(DIST / "lambda" / f"{mod}.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.write(LAMBDA / f"{mod}.py", f"{mod}.py")
            z.write(LAMBDA / "yuma_common.py", "yuma_common.py")
            for extra in EXTRA.get(mod, []):
                z.write(extra, extra.name)
            if vendored.exists():
                for f in vendored.rglob("*"):
                    if f.is_file():
                        z.write(f, f.relative_to(vendored))
        print("built", mod)
    shutil.copy(ROOT / "playbooks" / "asl" / "PB1-agent-containment.asl.json", DIST / "asl")


if __name__ == "__main__":
    main()
