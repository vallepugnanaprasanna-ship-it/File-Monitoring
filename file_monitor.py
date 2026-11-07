
import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hash_generator import generate_hash
from database import (
    get_all_files,
    update_status,
    add_event
)
from alerts import generate_alert


MONITOR_FOLDER = Path("monitorerd_files").resolve()


class FileMonitorHandler(FileSystemEventHandler):

    def check_file(self, file_path):

        file_path = os.path.normpath(file_path)

        for record in get_all_files():

            registered_path = os.path.normpath(
                record["file_path"]
            )

            if os.path.abspath(registered_path) != os.path.abspath(file_path):
                continue

            original_hash = record["file_hash"]

            if not os.path.exists(file_path):

                if record["status"] != "DELETED":
                    update_status(file_path, "DELETED")
                    generate_alert(file_path, "DELETED")

                return

            current_hash = generate_hash(file_path)

            if current_hash and current_hash != original_hash:

                if record["status"] != "MODIFIED":
                    update_status(file_path, "MODIFIED")
                    generate_alert(file_path, "MODIFIED")

            return

    def on_modified(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)


def start_monitoring():

    MONITOR_FOLDER.mkdir(parents=True, exist_ok=True)

    handler = FileMonitorHandler()
    observer = Observer()

    observer.schedule(
        handler,
        str(MONITOR_FOLDER),
        recursive=True
    )

    observer.start()

    print("Real-time file monitoring started!")

    return observer
