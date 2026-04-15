from setuptools import setup, find_packages

setup(
    name="recomet",
    version="1.0.0",
    description="Free, open-source OSINT & Recon Toolkit with CLI and GUI",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="jogeshd",
    url="https://github.com/jogeshd/recomet",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[],   # zero required deps — pure stdlib!
    entry_points={
        "console_scripts": [
            "recomet=recomet.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet",
        "Environment :: Console",
    ],
)
