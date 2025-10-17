from setuptools import setup, find_packages

setup(
    name="arkkeeper",
    version="0.2.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "ark=ark.cli:main",
        ],
    },
)
