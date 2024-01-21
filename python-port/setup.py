import setuptools
from setuptools import setup, find_packages

def readme():
    with open("README.rst") as fh:
        return fh.read()

setuptools.setup(name="sendpy",
      version="1.0.1",
      description="Email and text notification program",
      long_description=readme(),
      long_description_content_type="text/markdown",
      url="https://github.com/tdulcet/Send-Msg-CLI",
      author="Daniel Connelly and Teal Dulcet",
      author_email="connellyd2050@gmail.com",
      license="GPL",
      entry_points={
          'console_scripts': [
              'sendpy=sendpy.__main__:main'
          ]
      },
      packages=find_packages(),
      scripts=["bin/sendpy"],
      classifiers=[
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
          "Programming Language :: Python :: 3.9",
          "Programming Language :: Python :: 3.10",
          "Programming Language :: Python :: 3.11",
          "Programming Language :: Python :: 3.12",
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Operating System :: OS Independent",
      ],
      keywords="sendpy email e-mail send text notification g-mail",
      python_requires=">=3.6",
      include_package_data=True,
      project_urls={
          "Bug Reports": "https://github.com/tdulcet/Send-Msg-CLI",
          "Funding": "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NJ4PULABRVNCC",
          "Source": "https://github.com/tdulcet/Send-Msg-CLI",
      },
      )
