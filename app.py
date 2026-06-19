import os
import json
from datetime import datetime

from flask import Flask, request
from clickhouse_connect import get_client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

client = get_client(
    host=os.getenv("CLICKHOUSE_HOST"),
    port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
    username=os.getenv("CLICKHOUSE_USER"),
    password=os.getenv("CLICKHOUSE_PASSWORD"),
    database=os.getenv("CLICKHOUSE_DATABASE", "default"),
    secure=True
)


def flatten(data, parent_key="", sep="."):
    items = {}

    if isinstance(data, dict):
        for k, v in data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            items.update(flatten(v, new_key, sep=sep))

    elif isinstance(data, list):
        for i, v in enumerate(data):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            items.update(flatten(v, new_key, sep=sep))

    else:
        items[parent_key] = data

    return items

client.command("""
CREATE TABLE IF NOT EXISTS siem_logs
(
    received_at DateTime,
    payload_json String,
    flattened_json String
)
ENGINE = MergeTree
ORDER BY received_at
""")


@app.route("/", methods=["POST"])
def webhook():
    payload = request.get_json(silent=True)

    if payload is None:
        payload = {
            "raw_body": request.get_data(as_text=True)
        }

    flattened = flatten(payload)

    print("Headers:", dict(request.headers))
    print("Payload:", payload)
    print("Flattened:", flattened)

    client.insert(
        "siem_logs",
        [[
            datetime.utcnow(),
            json.dumps(payload),
            json.dumps(flattened)
        ]],
        column_names=[
            "received_at",
            "payload_json",
            "flattened_json"
        ]
    )

    return {"success": True}


app = app