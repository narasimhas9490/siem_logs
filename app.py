
import os
import json
import gzip
import base64
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from clickhouse_connect import get_client

load_dotenv()

app = Flask(__name__)

TABLE_NAME = os.getenv("CLICKHOUSE_TABLE", "webhook_events")

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
        database=os.getenv("CLICKHOUSE_DATABASE", "default"),
        secure=os.getenv("CLICKHOUSE_SECURE", "true").lower() == "true",
    )


def parse_request_body(req):
    raw = req.get_data()

    if (
        "gzip" in req.headers.get("Content-Encoding", "").lower()
        or raw.startswith(b"\x1f\x8b")
    ):
        raw = gzip.decompress(raw)

    return json.loads(raw.decode("utf-8", errors="replace"))


def flatten(obj, prefix=""):
    result = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}_{k}" if prefix else k
            result.update(flatten(v, key))

    elif isinstance(obj, list):
        result[prefix] = json.dumps(obj, ensure_ascii=False)

    else:
        result[prefix] = obj

    return result


def sanitize(name):
    return re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()


def decode_encoded_list(value):
    output = []

    for item in unquote(value).split(";"):
        item = item.strip()

        if not item:
            continue

        try:
            output.append(
                base64.b64decode(item).decode(
                    "utf-8",
                    errors="replace"
                )
            )
        except Exception:
            output.append(item)

    return output


def process_fields(data):
    result = {}

    for k, v in data.items():

        if (
            k in DECODE_FIELDS
            and isinstance(v, str)
        ):
            result[k] = json.dumps(
                decode_encoded_list(v),
                ensure_ascii=False
            )
        else:
            result[k] = (
                None if v is None else str(v)
            )

    return result


def ensure_table(client):
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS `{TABLE_NAME}`
        (
            received_at DateTime('UTC')
        )
        ENGINE = MergeTree
        ORDER BY received_at
        """
    )


def get_schema(client):
    rows = client.query(
        f"DESCRIBE TABLE `{TABLE_NAME}`"
    ).result_rows

    return {
        row[0]: row[1]
        for row in rows
    }


def add_missing_columns(client, columns):
    schema = get_schema(client)

    for col in columns:
        if col not in schema:
            client.command(
                f"""
                ALTER TABLE `{TABLE_NAME}`
                ADD COLUMN IF NOT EXISTS
                `{col}` Nullable(String)
                """
            )


def convert_datetime_columns(client, row):
    schema = get_schema(client)

    for column, column_type in schema.items():

        if (
            "DateTime" in column_type
            and column in row
            and isinstance(row[column], str)
        ):
            try:
                row[column] = datetime.fromisoformat(
                    row[column].replace(
                        "Z",
                        "+00:00"
                    )
                )
            except Exception:
                pass

    return row


@app.route("/", methods=["GET"])
def health():
    return {
        "status": "ok"
    }


@app.route("/", methods=["POST"])
def webhook():
    try:
        payload = parse_request_body(request)

        if not isinstance(payload, dict):
            return jsonify({
                "success": False,
                "error": "JSON root must be object"
            }), 400

        flat = flatten(payload)

        data = {
            sanitize(k): v
            for k, v in flat.items()
        }

        data = process_fields(data)

        client = get_ch_client()

        ensure_table(client)

        add_missing_columns(
            client,
            data.keys()
        )

        row = {
            "received_at": datetime.now(
                timezone.utc
            ),
            **data
        }

        row = convert_datetime_columns(
            client,
            row
        )

        columns = list(row.keys())

        values = [
            row[c]
            for c in columns
        ]

        client.insert(
            TABLE_NAME,
            [values],
            column_names=columns
        )

        return jsonify({
            "success": True
        })

    except Exception as exc:
        import traceback

        return jsonify({
            "success": False,
            "error": str(exc),
            "traceback": traceback.format_exc()
        }), 500


application = app

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )

