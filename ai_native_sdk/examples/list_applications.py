# SPDX-License-Identifier: MIT
"""List applications available to the configured API identity."""

import json
import os

from ai_native_sdk import Client


def main():
    client = Client(os.environ["AI_NATIVE_API_URL"], os.environ["AI_NATIVE_API_TOKEN"])
    print(json.dumps(client.applications(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
