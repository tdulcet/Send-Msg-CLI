import setuptools

def readme():
    with open("README.rst", "r") as fh:
        return fh.read()

setuptools.setup(name='sendpy',
      version='1.0',
      description='Email and text notification program',
      long_description=readme(),
      long_description_content_type="text/markdown",
      url="https://github.com/tdulcet/Send-Msg-CLI",
      author='Daniel Connelly',
      author_email='connellyd2050@gmail.com',
      license='GPL',
      packages=['sendpy'],
      scripts=['bin/sendpy'],
      classifiers=[
          "Programming Language :: Python :: 3.0",
          "Programming Language :: Python :: 3.1",
          "Programming Language :: Python :: 3.2",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Operating System :: OS Independent",
      ],
      keywords='sendpy email e-mail send text notification g-mail gmail',
      python_requires='>=3.0',
      include_package_data=True,
      zip_safe=False,
      project_urls={
          'Bug Reports': 'https://github.com/tdulcet/Send-Msg-CLI',
          'Funding': 'https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=W465UGL4BDZUN&c    urrency_code=USD&source=url',
          'Source': 'https://github.com/tdulcet/Send-Msg-CLI',
      },
      )
