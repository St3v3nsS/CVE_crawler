from setuptools import setup, find_packages

setup(name='Crawler',
      version='1.0',
      description='Python Crawler',
      author='Morosan Ionut',
      author_email='ionut.morosan@outlook.com',
      url='',
      packages=find_packages(include=['cve_crawler', 'cve_crawler.*']),
      install_requires=[
          're',
          'regex',
          'selectolax',
          'progressbar',
          'tqdm',
          'pymongo'
      ]
     )