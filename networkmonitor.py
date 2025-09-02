import time
import psutil
from filesystemmonitor import ThreatDatabase  

def monitor_network():
    db = ThreatDatabase("threat_detection.db")
    seen_connections = set()

    print("[INFO] Starting network monitoring... Press Ctrl+C to stop.")
    try:
        while True:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    conn_info = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                    if conn_info not in seen_connections:
                        seen_connections.add(conn_info)

                        description = f"New connection from {conn.laddr.ip}:{conn.laddr.port} to {conn.raddr.ip}:{conn.raddr.port}"
                        print(description)

                        db.log_event(
                            "Network Connection",                  
                            description,                           
                            "T1049",                               
                            "Low",                                
                            None,                                   
                            None,                                
                            "Monitored network connection event"    
                        )

            time.sleep(5)

    except KeyboardInterrupt:
        print("[INFO] Network monitoring stopped.")

if __name__ == "__main__":
    monitor_network()