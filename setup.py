import os

def build_exe():
    command = (
        'pyinstaller '
        '--onefile '
        '--noconsole '                   # <-- ye cmd window hide kar dega
        '--hidden-import=qdarkstyle '
        '--add-data "D:\\project\\pem\\image.py;." '
        '--icon "D:\\project\\new MX Signer\\new MX Signer\\MX SIgner\\logo2.ico" '
        'D:\\project\\pem\\cert_converter.py'
    )
    print("Running command:\n", command)
    os.system(command)

if __name__ == '__main__':
    build_exe()
