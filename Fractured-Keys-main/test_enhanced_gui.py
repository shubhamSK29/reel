#!/usr/bin/env python3
"""
Test the enhanced GUI to verify it displays properly
"""

import tkinter as tk
import sys
import os

def test_enhanced_gui():
    """Test that the enhanced GUI displays properly"""
    print("🎨 Testing Enhanced GUI...")
    
    try:
        from simple_gui import SimpleFracturedKeysGUI
        
        # Create a test window
        root = tk.Tk()
        root.title("Test - Enhanced GUI")
        
        # Create the enhanced GUI
        app = SimpleFracturedKeysGUI(root)
        
        print("✅ Enhanced GUI created successfully")
        print("🎨 You should see a modern, attractive interface with:")
        print("   • Dark blue header with white text")
        print("   • Professional color scheme")
        print("   • Styled tabs and buttons")
        print("   • Better spacing and layout")
        print("   • Modern input fields and progress bars")
        print("⏰ Window will close automatically in 5 seconds...")
        
        # Auto-close after 5 seconds
        root.after(5000, root.destroy)
        root.mainloop()
        
        return True
        
    except Exception as e:
        print(f"❌ Enhanced GUI test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🔐 Fractured Keys - Enhanced GUI Test")
    print("=" * 40)
    
    if test_enhanced_gui():
        print("\n🎉 Enhanced GUI test passed!")
        print("💡 You can now run: python3 start_app.py")
        print("🎨 The GUI should now look much more attractive and modern!")
        return True
    else:
        print("\n❌ Enhanced GUI test failed.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
