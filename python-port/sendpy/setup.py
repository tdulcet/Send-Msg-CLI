import setuptools

def readme():
    with open("README.rst", "r") as fh:
        return fh.read()

setuptools.setup(name='sendpy-danc2050',
      version='0.1',
      description='Email and text notification program',
      long_description=readme(),
      long_description_content_type="text/markdown",
      url="https://github.com/tdulcet/Send-Msg-CLI",
      author='Daniel Connelly',
      author_email='connellyd2050@gmail.com',
      license='GPL',
      #packages=setuptools.find_packages(),
      packages=['sendpy'],
      scripts=['bin/sendpy'],
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: GPL License",
          "Operating System :: OS Independent",
          "Development Status :: 3 - Alpha",
      ],
      keywords='sendpy email e-mail send text notification g-mail gmail',
      python_requires='>=3.0',
      include_package_data=True,
      zip_safe=False)
