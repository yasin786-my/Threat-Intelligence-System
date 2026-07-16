"""Safe simulator: refuses any target other than loopback or Docker private networks."""
import argparse, ipaddress, random, time, requests
def safe(host):
 ip=ipaddress.ip_address(host); return ip.is_loopback or ip.is_private
def main():
 p=argparse.ArgumentParser();p.add_argument("--url",default="http://127.0.0.1:5000/api/predict");p.add_argument("--rate",type=int,default=4);p.add_argument("--attack",action="store_true");p.add_argument("--username",default="admin");p.add_argument("--password",default="admin123");a=p.parse_args(); host=a.url.split("/")[2].split(":")[0]
 if not safe(host): raise SystemExit("Safety guard: target must be localhost or a private Docker address.")
 base=a.url.rsplit("/api/",1)[0]
 token=requests.post(base+"/api/auth/login",json={"username":a.username,"password":a.password},timeout=3).json().get("token")
 if not token: raise SystemExit("Could not obtain local demo token. Check credentials and server.")
 print(f"Generating safe local {'abnormal' if a.attack else 'normal'} telemetry to {a.url}")
 while True:
  rate=650 if a.attack else random.randint(1,8); d={"source_ip":"10.240.0.42","destination_ip":"127.0.0.1","destination_port":80,"protocol":"TCP","packet_size":random.randint(80,1400),"packet_rate":rate}
  try: print(requests.post(a.url,json=d,headers={"Authorization":"Bearer "+token},timeout=2).json())
  except Exception as e: print(e)
  time.sleep(1/max(a.rate,1))
if __name__=="__main__":main()
