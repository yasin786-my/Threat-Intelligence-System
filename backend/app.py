"""Thread Intelligence System API: local-first cyber traffic monitoring demo."""
from __future__ import annotations
import os
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_socketio import SocketIO
from api import api
from services import Store, SecurityService

def create_app() -> tuple[Flask, SocketIO]:
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv("SECRET_KEY", "tis-demo-secret"),
                      CONFIDENCE_THRESHOLD=float(os.getenv("CONFIDENCE_THRESHOLD", "0.80")),
                      BLOCK_DURATION_MINUTES=int(os.getenv("BLOCK_DURATION_MINUTES", "30")))
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    store = Store(os.getenv("MONGO_URI"))
    security = SecurityService(store, socketio, app.config)
    app.extensions["store"], app.extensions["security"] = store, security
    
    @app.before_request
    def block_middleware():
        if request.path in ("/api/health", "/api/auth/login") or request.method == "OPTIONS": return None
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        g.client_ip = ip
        block = store.active_block(ip)
        if block:
            return jsonify(status="blocked", message="Access denied", reason="Malicious activity detected"), 403

    @app.get("/")
    def root(): return jsonify(name="Thread Intelligence System", status="online")
    app.register_blueprint(api, url_prefix="/api")
    return app, socketio

app, socketio = create_app()
if __name__ == "__main__": socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
