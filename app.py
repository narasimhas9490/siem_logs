from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["POST"])
def webhook():
    print("Headers:", dict(request.headers))
    print("Body:", request.get_data(as_text=True))
    return {"success": True}

app = app
