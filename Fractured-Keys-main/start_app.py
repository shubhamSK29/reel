#!/usr/bin/env python3
"""
Fractured Keys - Simple Launcher
This script will start the GUI application with proper error handling
"""

import sys
import os
import subprocess

def main():
    """Main launcher function"""
    print("🔐 Fractured Keys - Starting Application...")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("stable_gui.py"):
        print("❌ Error: stable_gui.py not found!")
        print("Make sure you're running this from the Fractured-Keys-main directory.")
        input("Press Enter to exit...")
        return
    
    # Check Python version
    if sys.version_info < (3, 6):
        print("❌ Error: Python 3.6 or higher is required!")
        print(f"Current version: {sys.version}")
        input("Press Enter to exit...")
        return
    
    print(f"✅ Python version: {sys.version.split()[0]}")
    
    # Try to import required modules
    try:
        import tkinter
        print("✅ tkinter available")
    except ImportError:
        print("❌ Error: tkinter not available!")
        print("Please install tkinter: sudo apt-get install python3-tk")
        input("Press Enter to exit...")
        return
    
    try:
        import PIL
        print("✅ PIL (Pillow) available")
    except ImportError:
        print("❌ Error: PIL not available!")
        print("Installing Pillow...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'Pillow'])
            print("✅ Pillow installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install Pillow")
            input("Press Enter to exit...")
            return
    
    try:
        import cryptography
        print("✅ cryptography available")
    except ImportError:
        print("❌ Error: cryptography not available!")
        print("Installing cryptography...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cryptography'])
            print("✅ cryptography installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install cryptography")
            input("Press Enter to exit...")
            return
    
    try:
        import argon2
        print("✅ argon2 available")
    except ImportError:
        print("❌ Error: argon2 not available!")
        print("Installing argon2...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'argon2-cffi'])
            print("✅ argon2 installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install argon2")
            input("Press Enter to exit...")
            return
    
    print("\n🚀 Starting Fractured Keys GUI...")
    print("=" * 50)
    
    try:
        # Import and run the stable GUI
        from stable_gui import main as gui_main
        gui_main()
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure all files are in the same directory")
        print("2. Check that all dependencies are installed")
        print("3. Try running: pip install -r requirements.txt")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
