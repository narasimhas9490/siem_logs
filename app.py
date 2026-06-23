import os
import json
import gzip
import base64
import logging
import re

from urllib.parse import unquote
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from clickhouse_connect import get_client

load_dotenv()

app = Flask(**name**)

logging.basicConfig(level=logging.INFO)

TABLE_NAME = os.getenv(
"CLICKHOUSE_TABLE",
"webhook_events"
)

DECODE_FIELDS = {
"attackdata_rules",
"attackdata_ruleversions",
"attackdata_rulemessages",
"attackdata_ruletags",
"attackdata_ruledata",
"attackdata_ruleselectors",
"attackdata_ruleactions",
}

def parse_request_body(req):
raw = req.get_data()

```
app.logger.info(
    "Request size: %s bytes",
    len(raw)
)

encoding = req.headers.get(
    "Content-Encoding",
    ""
).lower()

app.logger.info(
    "Content-Encoding: %s",
    encoding
)

if "gzip" in encoding:
    app.logger.info(
        "Decompressing gzip payload"
    )

    raw = gzip.decompress(raw)

body = raw.decode(
    "utf-8",
    errors="replace"
)

app.logger.info(
    "First 500 chars: %s",
    body[:500]
)

return json.loads(body)
```

def decode_encoded_list(value):
if not isinstance(value, str):
return value

```
decoded_url = unquote(value)

result = []

for item in decoded_url.split(";"):

    item = item.strip()

    if not item:
        continue

    try:
        result.append(
            base64.b64decode(item).decode(
                "utf-8",
                errors="replace"
            )
        )

    except Exception:
        result.append(item)

return result
```

def process_special_fields(data):
processed = {}

```
for key, value in data.items():

    if (
        key in DECODE_FIELDS
        and isinstance(value, str)
    ):
        processed[key] = json.dumps(
            decode_encoded_list(value),
            ensure_ascii=False,
        )
    else:
        processed[key] = value

return processed
```

@app.route("/", methods=["POST"])
def webhook():

```
try:

    payload = parse_request_body(
        request
    )

    app.logger.info(
        "Payload type: %s",
        type(payload).__name__
    )

    if not isinstance(payload, dict):
        return jsonify(
            {
                "success": False,
                "error":
                    f"Expected JSON object, got "
                    f"{type(payload).__name__}"
            }
        ), 400

    # Existing flatten/process/clickhouse code here

    return jsonify(
        {
            "success": True
        }
    )

except gzip.BadGzipFile as exc:

    app.logger.exception(
        "Bad gzip payload"
    )

    return jsonify(
        {
            "success": False,
            "error": str(exc)
        }
    ), 400

except json.JSONDecodeError as exc:

    app.logger.exception(
        "JSON decode failed"
    )

    return jsonify(
        {
            "success": False,
            "error": str(exc)
        }
    ), 400

except Exception as exc:

    app.logger.exception(
        "Webhook failed"
    )

    return jsonify(
        {
            "success": False,
            "error": str(exc)
        }
    ), 500
```

# Vercel entrypoint

app = app
