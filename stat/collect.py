import json
import shelve

import websocket
import logging

API_URI = "wss://sing.ftiasch.xyz/connections"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s|%(levelname)s|%(message)s",
)
# {
#   "chains": [
#     "IEPL·台湾TW0·商宽C·均衡·1000M",
#     "ww-auto",
#     "ww",
#     "proxy-out"
#   ],
#   "download": 6331,
#   "id": "76ce9d48-9e9d-4f5a-b7cc-1731636e78e6",
#   "metadata": {
#     "destinationIP": "",
#     "destinationPort": "443",
#     "dnsMode": "normal",
#     "host": "client.wns.windows.com",
#     "network": "tcp",
#     "processPath": "",
#     "sourceIP": "192.168.1.200",
#     "sourcePort": "53260",
#     "type": "tun/tun-in"
#   },
#   "rule": "final",
#   "rulePayload": "",
#   "start": "2024-10-13T09:19:45.971965079Z",
#   "upload": 3374
# },


class Store:
    def __init__(self, db_path: str):
        self.db = shelve.open(db_path, "c")

    def __del__(self):
        self.db.close()

    def process(self, data):
        for conn in data["connections"]:
            self.db[conn["id"]] = conn
        logging.info("len(db)=%d", len(self.db))


if __name__ == "__main__":
    store = Store(db_path="conn")
    while True:
        ws = websocket.WebSocketApp(
            API_URI, on_message=lambda _, msg: store.process(json.loads(msg))
        )
        ws.run_forever()
