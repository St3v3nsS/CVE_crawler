import zipfile
import os
import urllib.request


def download_and_unzip(download_path, extract_path):
    url = 'https://github.com/offensive-security/exploitdb/archive/master.zip'

    urllib.request.urlretrieve(url, download_path)

    with zipfile.ZipFile(download_path, 'r') as zip_ref:
        print("In zip")
        zip_ref.extractall(extract_path)

    if os.path.exists(download_path):
        os.remove(download_path)
