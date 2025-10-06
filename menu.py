#!/usr/bin/env python3
#*********************************************************************************
#                                                                                *
# This file is part of the "CTM REST Asymmetric key demo" project.               *
# Use it at your own risk                                                        *
# Distributed under Apache 2.0 license                                           *
#                                                                                *
# Written by Erik LOUISE                                                         *
# Copyright © 2025 Thales Group                                                  *
#                                                                                *
#*********************************************************************************

# OBJECTIVE :
# - Provide a menu interface to select and execute any of the demo scripts

import os
import sys
import subprocess
from typing import Dict, List

class DemoMenu:
    def __init__(self):
        self.scripts = {
            "1": {
                "file": "1-create-keypairs-on-ctm.py",
                "title": "Create RSA Keypairs on CipherTrust Manager",
                "description": "Create an RSA-4096 asymmetric key in CipherTrust Manager via REST API"
            },
            "2": {
                "file": "2-encrypt-locally-with-rsa-pubkey-from-ctm.py", 
                "title": "Encrypt Locally with RSA Public Key from CTM",
                "description": "Retrieve RSA public key from CTM and encrypt payload locally"
            },
            "3": {
                "file": "2-encrypt-remotely-with-rsa-pubkey-on-ctm.py",
                "title": "Encrypt Remotely with RSA Public Key on CTM", 
                "description": "Encrypt payload remotely using RSA public key stored on CTM"
            },
            "4": {
                "file": "3-decrypt-remotely-with-rsa-privkey-on-ctm.py",
                "title": "Decrypt Remotely with RSA Private Key on CTM",
                "description": "Decrypt payload remotely using RSA private key stored on CTM"
            },
            "5": {
                "file": "4-compare-original-and-manipulated-payload.py",
                "title": "Compare Original and Manipulated Payload",
                "description": "Compare original payload with decrypted payload for integrity verification"
            }
        }
    
    def display_banner(self):
        """Display the application banner"""
        print("\n" + "="*80)
        print("         CipherTrust Manager REST Asymmetric Encryption Demo")
        print("                        by Erik LOUISE - Thales Group")
        print("="*80)
    
    def display_menu(self):
        """Display the main menu options"""
        print("\nAvailable Demo Scripts:")
        print("-" * 50)
        
        for key, script in self.scripts.items():
            print(f"  [{key}] {script['title']}")
            print(f"      {script['description']}")
            print()
    
    def display_workflow_info(self):
        """Display information about the recommended workflow"""
        print("\nRecommended Workflow:")
        print("-" * 30)
        print("1. First run script [1] to create RSA keypairs on CTM")
        print("2. Then run script [2] or [3] to encrypt your payload")
        print("3. Run script [4] to decrypt the encrypted payload")
        print("4. Finally run script [5] to verify payload integrity")
        print()
    
    def get_user_choice(self) -> str:
        """Get and validate user input"""
        while True:
            choice = input("Enter your choice (1-5), 'w' for workflow info, or 'q' to quit: ").strip().lower()
            
            if choice == 'q':
                return 'q'
            elif choice == 'w':
                return 'w'
            elif choice in self.scripts:
                return choice
            else:
                print("❌ Invalid choice. Please select 1-5, 'w' for workflow info, or 'q' to quit.")
    
    def execute_script(self, script_key: str):
        """Execute the selected script"""
        script_info = self.scripts[script_key]
        script_path = script_info["file"]
        
        if not os.path.exists(script_path):
            print(f"❌ Error: Script '{script_path}' not found!")
            return False
        
        print(f"\n🚀 Executing: {script_info['title']}")
        print(f"📄 Script: {script_path}")
        print("-" * 60)
        
        try:
            # Execute the script using subprocess
            result = subprocess.run([sys.executable, script_path], 
                                  capture_output=False, 
                                  text=True)
            
            print("-" * 60)
            if result.returncode == 0:
                print("✅ Script completed successfully!")
            else:
                print(f"❌ Script exited with code: {result.returncode}")
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"❌ Error executing script: {str(e)}")
            return False
    
    def run(self):
        """Main menu loop"""
        try:
            while True:
                self.display_banner()
                self.display_menu()
                
                choice = self.get_user_choice()
                
                if choice == 'q':
                    print("\n👋 Goodbye!")
                    break
                elif choice == 'w':
                    self.display_workflow_info()
                    input("\nPress Enter to continue...")
                    continue
                else:
                    self.execute_script(choice)
                    input("\nPress Enter to return to menu...")
                    
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted by user. Goodbye!")
        except Exception as e:
            print(f"\n❌ Unexpected error: {str(e)}")

def main():
    """Main entry point"""
    # Change to the script directory to ensure relative paths work
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    menu = DemoMenu()
    menu.run()

if __name__ == "__main__":
    main()