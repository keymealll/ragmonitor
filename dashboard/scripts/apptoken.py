"""Create, list or revoke the API tokens connected apps use to call POST /v1/chat.

  python scripts/apptoken.py create "Skerry travel site"   # prints the token once; put it in the app's .env
  python scripts/apptoken.py list
  python scripts/apptoken.py revoke <id>
"""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ragmon import store  # noqa: E402


def main(argv):
    store.init()
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "create" and len(argv) > 2:
        app_id, token = store.create_app(argv[2])
        print(f"Created app {app_id} ({argv[2]}). This token is shown once:\n\n  {token}\n")
        print("Put it in website-chatbot/.env as RAGMON_TOKEN=<token>")
    elif cmd == "list":
        for a in store.apps():
            used = datetime.fromtimestamp(a["last_used_ts"]).strftime("%H:%M") if a["last_used_ts"] else "never"
            print(f"{a['id']:>3}  {a['name']:<28} {a['token_prefix']}…  last used {used}  "
                  f"{a['conversations']} chats{'  REVOKED' if a['revoked'] else ''}")
    elif cmd == "revoke" and len(argv) > 2:
        print("Revoked." if store.revoke_app(int(argv[2])) else "No app with that id.")
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv)
