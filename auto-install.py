import os
import sys
import subprocess

def install_requirements():
    requirements_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    
    if os.path.exists(requirements_path):
        print("Installing dependencies from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r", requirements_path])
            print("Dependencies successfully installed.")
        except subprocess.CalledProcessError as e:
            print(f"Error installing dependencies : {e}")
    else:
        print("Error: the requirements.txt file cannot be found.")

def install_script():
    script_path = os.path.abspath("main.py") 
    batch_file_path = os.path.join(os.environ["USERPROFILE"], "pykspc.bat")

    # Créer le fichier batch
    with open(batch_file_path, 'w') as f:
        f.write(f'@echo off\npython "{script_path}" %*\n')

    print(f"Successful installation! You can now use 'pykspc' on the command line.")

    os.environ["PATH"] += os.pathsep + os.path.dirname(batch_file_path)
    print("Don't forget to restart your terminal or PC for the changes to take effect.")

if __name__ == "__main__":
    install_requirements()  
    install_script()
