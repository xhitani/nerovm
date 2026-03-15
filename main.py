import threading
import time
from dashboard import start as start_dashboard
from nero import main as nero_main

print("Starting NERO dashboard on port 8080...")
threading.Thread(target=start_dashboard, daemon=True).start()
time.sleep(2)

print("Starting NERO security engine...")
nero_main()
