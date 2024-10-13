import json
import shelve

import websocket
import logging
import signal

API_URI = "wss://sing.ftiasch.xyz/connections"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s|%(levelname)s|%(message)s",
)


class Store:
    def __init__(self, db_path: str):
        self.db = shelve.open(db_path, "c")

    def __del__(self):
        self.db.close()

    def process(self, data):
        for conn in data["connections"]:
            if conn["chains"][-1] == "proxy-out":
                self.db[conn["id"]] = conn
        logging.info("len(db)=%d", len(self.db))


is_running = True


def on_sigint(signum, frame):
    global is_running
    is_running = False
    ws.close()


if __name__ == "__main__":
    store = Store(db_path="conn")
    signal.signal(signal.SIGINT, on_sigint)
    while is_running:
        ws = websocket.WebSocketApp(
            API_URI, on_message=lambda _, msg: store.process(json.loads(msg))
        )
        ws.run_forever()
