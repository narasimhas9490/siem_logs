```python
import os
import json
import gzip
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from clickhouse_connect import get_client

load_dotenv()

app = Flask(__name__)

TABLE_NAME = os.getenv(
    "CLICKHOUSE_TABLE",
    "webhook_events",
)


def get_ch_client():
    return get_client(
        host=os.environ["CLICKHOUSE_HOST"],
        port=int(
            os.getenv(
                "CLICKHOUSE_PORT",
                "8443",
            )
        ),
        username=os.environ[
            "CLICKHOUSE_USER"
        ],
        password=os.environ[
            "CLICKHOUSE_PASSWORD"
        ],
        database=os.getenv(
            "CLICKHOUSE_DATABASE",
            "default",
        ),
        secure=os.getenv(
            "CLICKHOUSE_SECURE",
            "true",
        ).lower()
        == "true",
    )


def parse_request_body(req):
    raw = req.get_data()

    content_encoding = req.headers.get(
        "Content-Encoding",
        "",
    ).lower()

    is_gzip = (
        "gzip" in content_encoding
        or raw.startswith(b"\x1f\x8b")
    )

    if is_gzip:
        raw = gzip.decompress(raw)

    return json.loads(
        raw.decode("utf-8")
    )


def flatten(data, parent_key=""):
    result = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = (
                f"{parent_key}_{key}"
                if parent_key
                else key
            )

            result.update(
                flatten(
                    value,
                    new_key,
                )
            )

    elif isinstance(data, list):
        result[parent_key] = json.dumps(
            data,
            ensure_ascii=False,
        )

    else:
        result[parent_key] = (
            str(data)
            if data is not None
            else None
        )

    return result


def sanitize_column_name(name):
    sanitized = []

    for ch in name:
        if (
            ch.isalnum()
            or ch == "_"
        ):
            sanitized.append(ch)
        else:
            sanitized.append("_")

    return "".join(
        sanitized
    ).lower()


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
    result = client.query(
        f"""
        DESCRIBE TABLE {TABLE_NAME}
        """
    )

    return {
        row[0]
        for row in result.result_rows
    }


def add_missing_columns(
    client,
    columns,
):
    existing_columns = (
        get_existing_columns(client)
    )

    for column in columns:
        if (
            column
            not in existing_columns
        ):
            client.command(
                f"""
                ALTER TABLE {TABLE_NAME}
                ADD COLUMN IF NOT EXISTS
                `{column}`
                Nullable(String)
                """
            )


@app.route(
    "/",
    methods=["GET"],
)
def health():
    return jsonify(
        {
            "status": "ok",
        }
    )


@app.route(
    "/",
    methods=["POST"],
)
def webhook():
    try:
        payload = (
            parse_request_body(
                request
            )
        )

        if not isinstance(
            payload,
            dict,
        ):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": (
                            "JSON root "
                            "must be an object"
                        ),
                    }
                ),
                400,
            )

        flattened = flatten(
            payload
        )

        sanitized = {
            sanitize_column_name(
                key
            ): value
            for key, value in (
                flattened.items()
            )
        }

        client = (
            get_ch_client()
        )

        ensure_table_exists(
            client
        )

        add_missing_columns(
            client,
            sanitized.keys(),
        )

        row = {
            "received_at": datetime.now(
                timezone.utc
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            **sanitized,
        }

        client.insert(
            TABLE_NAME,
            [list(row.values())],
            column_names=list(
                row.keys()
            ),
        )

        return jsonify(
            {
                "success": True,
                "columns_inserted": len(
                    sanitized
                ),
            }
        )

    except gzip.BadGzipFile:
        return (
            jsonify(
                {
                    "success": False,
                    "error": (
                        "Invalid gzip payload"
                    ),
                }
            ),
            400,
        )

    except json.JSONDecodeError:
        return (
            jsonify(
                {
                    "success": False,
                    "error": (
                        "Invalid JSON payload"
                    ),
                }
            ),
            400,
        )

    except Exception as exc:
        app.logger.exception(
            "Webhook processing failed"
        )

        return (
            jsonify(
                {
                    "success": False,
                    "error": str(exc),
                }
            ),
            500,
        )


app = app
```
