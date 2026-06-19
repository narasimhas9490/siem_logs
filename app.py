import os
import json
import gzip
import re
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from clickhouse_connect import get_client


# Load .env for local development.
# Vercel uses Environment Variables automatically.
load_dotenv()


app = Flask(__name__)


TABLE_NAME = os.getenv(
    "CLICKHOUSE_TABLE",
    "webhook_events"
)


def get_ch_client():
    required = [
        "CLICKHOUSE_HOST",
        "CLICKHOUSE_USER",
        "CLICKHOUSE_PASSWORD",
    ]

    missing = [
        key
        for key in required
        if not os.getenv(key)
    ]

    if missing:
        raise RuntimeError(
            "Missing environment variables: "
            + ", ".join(missing)
        )

    return get_client(
        host=os.environ["CLICKHOUSE_HOST"],
        port=int(
            os.getenv(
                "CLICKHOUSE_PORT",
                "8443",
            )
        ),
        username=os.environ["CLICKHOUSE_USER"],
        password=os.environ["CLICKHOUSE_PASSWORD"],
        database=os.getenv(
            "CLICKHOUSE_DATABASE",
            "default",
        ),
        secure=os.getenv(
            "CLICKHOUSE_SECURE",
            "true",
        ).lower() == "true",
    )


def parse_request_body(req):
    raw = req.get_data()

    encoding = req.headers.get(
        "Content-Encoding",
        "",
    ).lower()

    if (
        "gzip" in encoding
        or raw.startswith(b"\x1f\x8b")
    ):
        raw = gzip.decompress(raw)

    return json.loads(
        raw.decode("utf-8")
    )


def flatten(data, parent=""):
    output = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = (
                f"{parent}_{key}"
                if parent
                else key
            )

            output.update(
                flatten(
                    value,
                    new_key,
                )
            )

    elif isinstance(data, list):
        output[parent] = json.dumps(
            data,
            ensure_ascii=False,
        )

    else:
        output[parent] = (
            str(data)
            if data is not None
            else None
        )

    return output


def sanitize_column_name(name):
    name = re.sub(
        r"[^a-zA-Z0-9_]",
        "_",
        name,
    )

    return name.lower()


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


def get_existing_columns(client):
    result = client.query(
        f"DESCRIBE TABLE `{TABLE_NAME}`"
    )

    return {
        row[0]
        for row in result.result_rows
    }


def add_missing_columns(client, columns):
    existing = get_existing_columns(client)

    for column in columns:
        if column not in existing:
            client.command(
                f"""
                ALTER TABLE `{TABLE_NAME}`
                ADD COLUMN IF NOT EXISTS
                `{column}`
                Nullable(String)
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
        payload = parse_request_body(request)

        if not isinstance(payload, dict):
            return jsonify(
                {
                    "success": False,
                    "error": (
                        "JSON root must be an object"
                    ),
                }
            ), 400


        flattened = flatten(payload)


        data = {
            sanitize_column_name(key): value
            for key, value in flattened.items()
        }


        client = get_ch_client()


        ensure_table_exists(client)


        add_missing_columns(
            client,
            data.keys(),
        )


        row = {
            "received_at": datetime.now(
                timezone.utc
            ),
            **data,
        }


        columns = list(row.keys())


        client.insert(
            TABLE_NAME,
            [
                [
                    row[column]
                    for column in columns
                ]
            ],
            column_names=columns,
        )


        return jsonify(
            {
                "success": True,
                "columns_inserted": len(data),
            }
        )


    except gzip.BadGzipFile:
        return jsonify(
            {
                "success": False,
                "error": "Invalid gzip payload",
            }
        ), 400


    except json.JSONDecodeError:
        return jsonify(
            {
                "success": False,
                "error": "Invalid JSON payload",
            }
        ), 400


    except Exception as exc:
        app.logger.exception(
            "Webhook processing failed"
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 500



# Vercel entrypoint
app = app
