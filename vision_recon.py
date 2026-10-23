import cv2
import numpy as np
import time
import proximity, sensors
# This is where the phone's camera frames live
frame_container = [None]
def process_phone_frame(frame_bytes):
    global frame_container
    try:
        nparr = np.frombuffer(frame_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if frame is not None:
            # DEBUG: Show how many devices NERO can actually see
            dev_count = len(proximity.nearby_devices)
            cv2.putText(frame, f"SENSORS ACTIVE: {dev_count} DEVICES", (10, 20), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 0), 1)

            best_mac, best_rssi = None, -100
            for mac, info in proximity.nearby_devices.items():
                if info['rssi'] > best_rssi:
                    best_rssi, best_mac = info['rssi'], mac

            # Show the strongest signal found, even if it's far away
            if best_mac:
                cv2.putText(frame, f"STRONGEST: {best_rssi}dBm", (10, 40), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)

            # LOWERED THRESHOLD: -60 is easier to trigger than -45
            if best_rssi > -60:
                target_ip = "UNKNOWN"
                for ip, dev in sensors.devices.items():
                    if dev.get('mac') == best_mac:
                        target_ip = ip
                
                # Visual HUD
                cv2.rectangle(frame, (30, 30), (frame.shape[1]-30, frame.shape[0]-30), (0, 0, 255), 2)
                cv2.putText(frame, f"DETECTED: {target_ip}", (50, 80), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)

            frame_container[0] = frame
    except Exception as e:
        print(f"Vision Error: {e}")
def get_processed_stream():
    """
    Generator function for the Flask /video_feed route.
    This creates the 'live pipe' that the dashboard stays connected to.
    """
    import time
    global frame_container

    while True:
        # Access the frame sent by the phone
        frame = frame_container[0]
        
        if frame is not None:
            # 1. Encode the frame as a JPEG
            ret, buffer = cv2.imencode('.jpg', frame)
            
            if ret:
                # 2. Convert to bytes and yield in the multipart format Flask expects
                frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        else:
            # 3. Fallback: If no frame is uploaded yet, show a black loading screen
            # This prevents the browser from showing a broken image icon
            blank_frame = np.zeros((480, 640, 3), dtype=np.uint8)
            cv2.putText(blank_frame, "SYSTEM READY: WAITING FOR DATA...", (100, 240), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            
            ret, buffer = cv2.imencode('.jpg', blank_frame)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

        # 4. CRITICAL: Control the frame rate (FPS)
        # 0.1s delay = 10 FPS. This keeps the CPU low and syncs with the phone's upload speed.
        time.sleep(0.1)
def start():
    print("[VISION] Recon System Online.")
