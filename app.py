import os
import json
import gzip
from datetime import datetime

from flask import Flask, request, jsonify
from clickhouse_connect import get_client

app = Flask(__name__)

TABLE_NAME = "webhook_events"


def get_ch_client():
    return get_client(
        host=os.environ["CLICKHOUSE_HOST"],
        port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
        username=os.environ["CLICKHOUSE_USER"],
        password=os.environ["CLICKHOUSE_PASSWORD"],
        database=os.getenv("CLICKHOUSE_DATABASE", "default"),
        secure=True,
    )


def parse_request_body(req):
    raw = req.get_data()

    content_encoding = req.headers.get("Content-Encoding", "").lower()

    if "gzip" in content_encoding:
        raw = gzip.decompress(raw)

    text = raw.decode("utf-8")

    return json.loads(text)


def flatten(data, parent_key=""):
    result = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}_{key}" if parent_key else key
            result.update(flatten(value, new_key))

    elif isinstance(data, list):
        result[parent_key] = json.dumps(data)

    else:
        result[parent_key] = str(data) if data is not None else None

    return result


def sanitize_column_name(name):
    sanitized = []

    for ch in name:
        if ch.isalnum() or ch == "_":
            sanitized.append(ch)
        else:
            sanitized.append("_")

    return "".join(sanitized).lower()


def ensure_table_exists(client):
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME}
        (
            received_at DateTime
        )
        ENGINE = MergeTree
        ORDER BY received_at
        """
    )


def get_existing_columns(client):
    result = client.query(f"DESCRIBE TABLE {TABLE_NAME}")
    return {row[0] for row in result.result_rows}


def add_missing_columns(client, columns):
    existing = get_existing_columns(client)

    for column in columns:
        if column not in existing:
            client.command(
                f"""
                ALTER TABLE {TABLE_NAME}
                ADD COLUMN IF NOT EXISTS `{column}` Nullable(String)
                """
            )


@app.route("/", methods=["POST"])
def webhook():
    try:
        payload = parse_request_body(request)

        flat_data = flatten(payload)

        sanitized = {
            sanitize_column_name(k): v
            for k, v in flat_data.items()
        }

        client = get_ch_client()

        ensure_table_exists(client)
        add_missing_columns(client, sanitized.keys())

        row = {
            "received_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            **sanitized,
        }

        client.insert(
            TABLE_NAME,
            [list(row.values())],
            column_names=list(row.keys()),
        )

        return jsonify(
            {
                "success": True,
                "columns_inserted": len(sanitized),
            }
        )

    except Exception as e:
        print("ERROR:", str(e))
        return jsonify(
            {
                "success": False,
                "error": str(e),
            }
        ), 500


@app.route("/", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok"
        }
    )


app = app