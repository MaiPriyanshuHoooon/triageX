"""
Live-Reload Development Launcher for Forensic Tool
Automatically restarts the application when .py, .ui, or .qss files change

Usage:
    python run_dev.py

Features:
    - Watches for file changes in .py, .ui, .qss files
    - Auto-restarts application on save
    - Debouncing to prevent multiple restarts
    - Clean subprocess management
"""

import sys
import os
import subprocess
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class AppReloader(FileSystemEventHandler):
    """File system event handler for auto-reloading"""

    def __init__(self, script_path):
        self.script_path = script_path
        self.process = None
        self.last_restart = 0
        self.debounce_seconds = 1.0  # Prevent multiple restarts within 1 second
        self.start_app()

    def start_app(self):
        """Start or restart the application"""
        # Kill existing process
        if self.process:
            print("🔄 Restarting application...")
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

        # Start new process
        print("🚀 Starting application...")
        self.process = subprocess.Popen(
            [sys.executable, self.script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        print(f"✅ Application started (PID: {self.process.pid})")
        print("📁 Watching for file changes (.py, .ui, .qss)...")
        print("=" * 60)

    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return

        # Check if file extension is one we care about
        file_path = Path(event.src_path)
        if file_path.suffix not in ['.py', '.ui', '.qss']:
            return

        # Debounce: prevent multiple restarts for rapid file saves
        current_time = time.time()
        if current_time - self.last_restart < self.debounce_seconds:
            return

        self.last_restart = current_time

        # Show which file triggered the reload
        rel_path = os.path.relpath(event.src_path)
        print(f"\n📝 File changed: {rel_path}")

        # Restart the application
        self.start_app()

    def stop(self):
        """Stop the application process"""
        if self.process:
            print("\n🛑 Stopping application...")
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def main():
    """Main entry point for development launcher"""
    print("=" * 60)
    print("🔧 Forensic Tool - Live Development Mode")
    print("=" * 60)
    print("This launcher will automatically restart the app when files change.")
    print("Watching: *.py, *.ui, *.qss files")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()

    # Path to the main application script
    script_path = os.path.join(os.path.dirname(__file__), 'main.py')

    if not os.path.exists(script_path):
        print(f"❌ Error: {script_path} not found!")
        sys.exit(1)

    # Create file watcher
    event_handler = AppReloader(script_path)
    observer = Observer()

    # Watch current directory and subdirectories
    watch_path = os.path.dirname(__file__) or '.'
    observer.schedule(event_handler, watch_path, recursive=True)
    observer.start()

    try:
        # Keep the script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        print("=" * 60)
        print("🛑 Shutting down development server...")
        event_handler.stop()
        observer.stop()
        observer.join()
        print("✅ Development server stopped")
        print("=" * 60)


if __name__ == "__main__":
    main()
