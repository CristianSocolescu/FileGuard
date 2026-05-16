import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from detector import analyze_directory

class FileGuardHandler(FileSystemEventHandler):
    # this will trigger when a new file appears
    def on_created(self, event):
        if not event.is_directory:
            print(f"\n[!] New File: -> {event.src_path}")
            print("[*] Start tracking with WAZUH..")
            
       
            analyze_directory("./to_scan")
            
            print("[+] Waiting for new files...\n")

if __name__ == "__main__":
    FOLDER_TO_WATCH = "./to_scan"
    
    if not os.path.exists(FOLDER_TO_WATCH):
        os.makedirs(FOLDER_TO_WATCH)

    event_handler = FileGuardHandler()
    observer = Observer()
    observer.schedule(event_handler, FOLDER_TO_WATCH, recursive=False)
    observer.start()
    
    print("==================================================")
    print("FileGuard Service is ACTIV")
    print(f"Watching folder: {FOLDER_TO_WATCH}")
    print("==================================================")
    
    try:
        # keep the program running in the background
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[-] FileGuard Service stopped.")
    observer.join()