```python
import os
import json
import gzip
import base64
import re
from urllib.parse import unquote
from datetime import datetime

import pandas as pd
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from clickhouse_connect import get_client

load_dotenv()

app = Flask(__name__)

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


def get_ch_client():
    return get_client(
        host=os.getenv("CLICKHOUSE_HOST"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
        username=os.getenv("CLICKHOUSE_USER"),
        password=os.getenv("CLICKHOUSE_PASSWORD"),
        database=os.getenv(
            "CLICKHOUSE_DATABASE",
            "default"
        ),
        secure=os.getenv(
            "CLICKHOUSE_SECURE",
            "true"
        ).lower() == "true",
    )


def parse_body(req):
    raw = req.get_data()

    if (
        "gzip"
        in req.headers.get(
            "Content-Encoding",
            ""
        ).lower()
    ):
        raw = gzip.decompress(raw)

    return json.loads(
        raw.decode(
            "utf-8",
            errors="replace"
        )
    )


def flatten(data, prefix=""):
    result = {}

    if isinstance(data, dict):
        for k, v in data.items():
            key = (
                f"{prefix}_{k}"
                if prefix
                else k
            )
            result.update(
                flatten(v, key)
            )

    elif isinstance(data, list):
        result[prefix] = json.dumps(
            data,
            ensure_ascii=False
        )

    else:
        result[prefix] = data

    return result


def sanitize(name):
    return re.sub(
        r"[^a-zA-Z0-9_]",
        "_",
        name
    ).lower()


def decode_special(value):
    values = []

    for item in unquote(value).split(";"):
        item = item.strip()

        if not item:
            continue

        try:
            values.append(
                base64.b64decode(item)
                .decode(
                    "utf-8",
                    errors="replace"
                )
            )
        except Exception:
            values.append(item)

    return values


def process_fields(data):
    output = {}

    for k, v in data.items():

        if (
            k in DECODE_FIELDS
            and isinstance(v, str)
        ):
            output[k] = json.dumps(
                decode_special(v),
                ensure_ascii=False
            )
        else:
            output[k] = (
                None
                if v is None
                else str(v)
            )

    return output


def ensure_table(client):
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS `{TABLE_NAME}`
        (
            received_at Nullable(String)
        )
        ENGINE = MergeTree
        ORDER BY tuple()
        """
    )


def existing_columns(client):
    rows = client.query(
        f"DESCRIBE TABLE `{TABLE_NAME}`"
    ).result_rows

    return {
        row[0]
        for row in rows
    }


def add_columns(client, cols):
    current = existing_columns(client)

    for col in cols:
        if col not in current:
            client.command(
                f"""
                ALTER TABLE `{TABLE_NAME}`
                ADD COLUMN IF NOT EXISTS
                `{col}` Nullable(String)
                """
            )


@app.route("/", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "table": TABLE_NAME,
        }
    )


@app.route("/", methods=["POST"])
def webhook():

    try:

        payload = parse_body(request)

        if not isinstance(
            payload,
            dict
        ):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "JSON root must be object",
                    }
                ),
                400,
            )

        flat = flatten(payload)

        data = {
            sanitize(k): v
            for k, v in flat.items()
        }

        data = process_fields(data)

        data["received_at"] = datetime.utcnow().isoformat()

        client = get_ch_client()

        ensure_table(client)

        add_columns(
            client,
            data.keys()
        )

        df = pd.DataFrame([data])

        client.insert_df(
            TABLE_NAME,
            df
        )

        return jsonify(
            {
                "success": True,
                "columns_inserted": len(data),
            }
        )

    except Exception as exc:

        import traceback

        return (
            jsonify(
                {
                    "success": False,
                    "error": str(exc),
                    "type": type(exc).__name__,
                    "traceback": traceback.format_exc(),
                }
            ),
            500,
        )


application = app

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        ),
    )
```
