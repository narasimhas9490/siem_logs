
import os
import json
import gzip
import base64
import re
import traceback
from datetime import datetime, timezone
from urllib.parse import unquote

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

URL_DECODE_FIELDS = {
    "httpmessage_requestheaders",
    "httpmessage_responseheaders",
    "httpmessage_query",
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


def parse_request_body(req):
    raw = req.get_data()

    if (
        "gzip" in req.headers.get(
            "Content-Encoding",
            ""
        ).lower()
        or raw.startswith(b"\x1f\x8b")
    ):
        raw = gzip.decompress(raw)

    return json.loads(
        raw.decode(
            "utf-8",
            errors="replace"
        )
    )


def flatten(data, parent=""):
    result = {}

    if isinstance(data, dict):

        for key, value in data.items():

            new_key = (
                f"{parent}_{key}"
                if parent
                else key
            )

            result.update(
                flatten(
                    value,
                    new_key
                )
            )

    elif isinstance(data, list):

        result[parent] = json.dumps(
            data,
            ensure_ascii=False
        )

    else:

        result[parent] = data

    return result


def sanitize_column_name(name):
    return re.sub(
        r"[^a-zA-Z0-9_]",
        "_",
        name
    ).lower()


def decode_encoded_list(value):
    decoded_items = []

    decoded_url = unquote(value)

    for item in decoded_url.split(";"):

        item = item.strip()

        if not item:
            continue

        try:
            decoded_items.append(
                base64.b64decode(item)
                .decode(
                    "utf-8",
                    errors="replace"
                )
            )
        except Exception:
            decoded_items.append(item)

    return decoded_items


def process_fields(data):
    processed = {}

    for key, value in data.items():

        if value is None:
            processed[key] = None
            continue

        if (
            key in DECODE_FIELDS
            and isinstance(value, str)
        ):
            processed[key] = json.dumps(
                decode_encoded_list(value),
                ensure_ascii=False
            )

        elif (
            key in URL_DECODE_FIELDS
            and isinstance(value, str)
        ):
            processed[key] = unquote(value)

        else:
            processed[key] = str(value)

    return processed


def ensure_table_exists(client):

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

    result = client.query(
        f"DESCRIBE TABLE `{TABLE_NAME}`"
    )

    return {
        row[0]: row[1]
        for row in result.result_rows
    }


def add_missing_columns(client, columns):

    schema = get_schema(client)

    for column in columns:

        if column not in schema:

            client.command(
                f"""
                ALTER TABLE `{TABLE_NAME}`
                ADD COLUMN IF NOT EXISTS
                `{column}` Nullable(String)
                """
            )


def convert_datetime_columns(client, row):

    schema = get_schema(client)

    for column, column_type in schema.items():

        if (
            "DateTime" in str(column_type)
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

    return jsonify({
        "status": "ok",
        "table": TABLE_NAME
    })


@app.route("/", methods=["POST"])
def webhook():

    try:

        payload = parse_request_body(
            request
        )

        if not isinstance(
            payload,
            dict
        ):
            return jsonify({
                "success": False,
                "error": "JSON root must be object"
            }), 400

        flattened = flatten(payload)

        data = {
            sanitize_column_name(k): v
            for k, v in flattened.items()
        }

        data = process_fields(data)

        client = get_ch_client()

        ensure_table_exists(client)

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

        columns = list(
            row.keys()
        )

        values = [
            row[col]
            for col in columns
        ]

        client.insert(
            TABLE_NAME,
            [values],
            column_names=columns
        )

        return jsonify({
            "success": True,
            "columns_inserted": len(data)
        })

    except gzip.BadGzipFile as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 400

    except json.JSONDecodeError as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 400

    except Exception as exc:

        app.logger.exception(
            "Webhook processing failed"
        )

        return jsonify({
            "success": False,
            "error": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc()
        }), 500


application = app

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        )
    )

