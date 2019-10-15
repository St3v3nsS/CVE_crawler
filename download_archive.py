import zipfile
import os
import urllib.request
import progressbar
from tqdm import tqdm

class MyProgressBar():
    def __init__(self):
        self.pbar = None

    def __call__(self, block_num, block_size, total_size):
        if not self.pbar:
            self.pbar=progressbar.ProgressBar(maxval=total_size)
            self.pbar.start()

        downloaded = block_num * block_size
        if downloaded < total_size:
            self.pbar.update(downloaded)
        else:
            self.pbar.finish()

def download_and_unzip(download_path, extract_path):
    url = 'https://github.com/offensive-security/exploitdb/archive/master.zip'

    try:
        urllib.request.urlretrieve(url, download_path, MyProgressBar())
  
        with zipfile.ZipFile(download_path, 'r') as zip_ref:
            for member in tqdm(zip_ref.infolist(), desc='Extracting '):
                try:
                    zip_ref.extract(member, extract_path)
                except zipfile.error as e:
                    pass

        if os.path.exists(download_path):
            os.remove(download_path)

    except ValueError as e:
            print(e)