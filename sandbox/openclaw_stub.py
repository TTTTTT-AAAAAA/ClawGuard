import argparse
import json
from pathlib import Path
from time import sleep


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["run", "analyze", "export"])
    parser.add_argument("--mode", default="safe")
    parser.add_argument("--input", default="request.json")
    args = parser.parse_args()

    input_dir = Path("/workspace/input")
    output_dir = Path("/workspace/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    sleep(0.2)
    result = {
        "engine": "openclaw_stub",
        "action": args.action,
        "mode": args.mode,
        "input_exists": (input_dir / args.input).exists(),
        "risk_score": 12 if args.mode == "safe" else 35,
        "summary": "OpenClaw stub completed inside sandbox.",
        "recommendations": ["keep network disabled for student tasks", "review medium-risk masked findings"],
    }
    (output_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()

