from __future__ import annotations
import csv, io, os
from datetime import datetime, timedelta, timezone
from functools import wraps
import jwt
from flask import Blueprint, current_app, jsonify, request, Response
api=Blueprint("api",__name__)
def store(): return current_app.extensions["store"]
def sec(): return current_app.extensions["security"]
def auth(role: str | None=None):
 def deco(fn):
  @wraps(fn)
  def wrapped(*a,**kw):
   token=request.headers.get("Authorization","").removeprefix("Bearer ")
   try: user=jwt.decode(token,current_app.config["SECRET_KEY"],algorithms=["HS256"])
   except Exception: return jsonify(error="Authentication required"),401
   if role and user.get("role") != role: return jsonify(error="Administrator role required"),403
   return fn(*a,**kw)
  return wrapped
 return deco
@api.post("/auth/login")
def login():
 data=request.get_json(silent=True) or {}; username=data.get("username",""); password=data.get("password","")
 if not ((username=="admin" and password=="admin123") or (username=="viewer" and password=="viewer123")): return jsonify(error="Invalid credentials"),401
 role="admin" if username=="admin" else "viewer"; token=jwt.encode({"sub":username,"role":role,"exp":datetime.now(timezone.utc)+timedelta(hours=12)},current_app.config["SECRET_KEY"],algorithm="HS256")
 return jsonify(token=token,user={"username":username,"role":role})
@api.get("/health")
def health(): return jsonify(status="healthy",service="thread-intelligence-system")
@api.get("/dashboard")
@auth()
def dashboard(): return jsonify(sec().dashboard())
@api.get("/traffic")
@auth()
def traffic():
 q=request.args.get("search","").lower(); rows=store().all("packets"); return jsonify([r for r in rows if not q or q in str(r).lower()][:200])
@api.get("/alerts")
@auth()
def alerts(): return jsonify(store().all("alerts")[:100])
@api.get("/statistics")
@auth()
def statistics(): return jsonify(sec().statistics())
@api.get("/blocked-ips")
@auth()
def blocked(): return jsonify(store().all("blocked_ips"))
@api.post("/predict")
@auth()
def predict():
 data=request.get_json(force=True)
 # Telemetry can describe a source distinct from the Docker gateway making
 # the HTTP request.  Enforce the demo block list against that reported
 # source so subsequent simulated packets are rejected consistently.
 source_ip=data.get("source_ip")
 if source_ip and store().active_block(source_ip):
  return jsonify(status="blocked",message="Access denied",reason="Malicious activity detected"),403
 return jsonify(sec().ingest(data))
@api.post("/block-ip")
@auth("admin")
def block():
 d=request.get_json(force=True); ip=d.get("ip")
 if not ip:return jsonify(error="ip is required"),400
 return jsonify(sec().block(ip,d,d.get("reason","Manual administrative block"))),201
@api.post("/unblock-ip")
@auth("admin")
def unblock():
 ip=(request.get_json(force=True)).get("ip"); return (jsonify(status="unblocked",ip=ip),200) if store().unblock(ip) else (jsonify(error="Active block not found"),404)
@api.get("/attack-history")
@auth()
def history(): return jsonify([r for r in store().all("packets") if r.get("attack_type")!="Normal"])
@api.get("/reports/csv")
@auth()
def report_csv():
 out=io.StringIO(); rows=store().all("packets"); writer=csv.DictWriter(out,fieldnames=sorted({k for r in rows for k in r}),extrasaction="ignore"); writer.writeheader();writer.writerows(rows)
 return Response(out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=traffic-report.csv"})
@api.get("/settings")
@auth()
def settings(): return jsonify(confidence_threshold=current_app.config["CONFIDENCE_THRESHOLD"],block_duration_minutes=current_app.config["BLOCK_DURATION_MINUTES"])
@api.put("/settings")
@auth("admin")
def update_settings():
 d=request.get_json(force=True); current_app.config["CONFIDENCE_THRESHOLD"]=float(d.get("confidence_threshold",current_app.config["CONFIDENCE_THRESHOLD"])); current_app.config["BLOCK_DURATION_MINUTES"]=int(d.get("block_duration_minutes",current_app.config["BLOCK_DURATION_MINUTES"])); return settings()
