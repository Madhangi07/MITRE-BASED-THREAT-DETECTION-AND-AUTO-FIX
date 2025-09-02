import threading
import time
import json

from filesystemmonitor import main as filesystem_main
from networkmonitor import monitor_network
from processmonitor import ProcessWatcher
from eventcorrelator import EventCorrelator
from securitydashboard import run_dashboard

with open("compact_d3fend.json", "r") as f:
    d3fend_map = json.load(f)

def run_filesystem():
    filesystem_main()

def run_network():
    monitor_network()

def run_process():
    watcher = ProcessWatcher()
    watcher.watch_processes()

def run_correlator():
    correlator = EventCorrelator(d3fend_map)
    correlator.run(60)

def run_ui():
    run_dashboard()

if __name__ == "__main__":  
    threads = []

    t1 = threading.Thread(target=run_filesystem, daemon=True)
    t2 = threading.Thread(target=run_network, daemon=True)
    t3 = threading.Thread(target=run_process, daemon=True)
    t4 = threading.Thread(target=run_correlator, daemon=True)
    t5 = threading.Thread(target=run_ui, daemon=True)

    threads.extend([t1, t2, t3, t4, t5])

    for t in threads:
        t.start()

    print("[INFO] Security Monitoring Suite + Dashboard Started at http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping all monitors...")