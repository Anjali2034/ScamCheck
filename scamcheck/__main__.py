"""CLI:  python -m scamcheck "suspicious message text"   [--image path.png]"""
import argparse
import json
import mimetypes
import sys

from scamcheck.agent import Investigation, format_for_whatsapp


def printer(e: dict) -> None:
    t = e["type"]
    if t == "thinking":
        print(f"\033[2m💭 {e['text']}\033[0m")
    elif t == "tool_call" and e["name"] != "submit_verdict":
        print(f"🔧 {e['name']}({json.dumps(e['input'], ensure_ascii=False)[:160]})")
    elif t == "tool_result":
        print(f"   ↳ {json.dumps(e['result'], ensure_ascii=False, default=str)[:300]}")
    elif t == "screenshot":
        print(f"📸 screenshot saved: {e['path']}")
    elif t == "error":
        print(f"❌ {e['message']}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="scamcheck")
    ap.add_argument("text", nargs="?", default="")
    ap.add_argument("--image")
    args = ap.parse_args()
    images = []
    if args.image:
        images.append((open(args.image, "rb").read(), mimetypes.guess_type(args.image)[0] or "image/png"))
    inv = Investigation()
    result = inv.run(text=args.text, images=images, emit=printer)
    print("\n" + "=" * 60 + "\n" + format_for_whatsapp(result))
    while True:
        try:
            follow = input("\nFollow-up (Enter to quit): ").strip()
        except EOFError:
            break
        if not follow:
            break
        print("\n" + format_for_whatsapp(inv.run(text=follow, emit=printer)))


if __name__ == "__main__":
    main()
