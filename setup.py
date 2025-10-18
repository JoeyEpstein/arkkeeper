from setuptools import setup, find_packages
from pathlib import Path

readme = Path("README.md")
long_description = readme.read_text(encoding="utf-8") if readme.exists() else ""

setup(
    name="arkkeeper",
    version="0.2.0",
    author="Arkkeeper Contributors",
    description="Find, score, and rotate credentials on your dev machine without exfiltrating secrets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/JoeyEpstein/arkkeeper",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    package_data={"ark": ["rules/*.yml"]},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
        "python-dateutil>=2.8.0",
        "jinja2>=3.1.0",
        "markdown>=3.5.0",
        "icalendar>=5.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "ruff>=0.1.0",
            "mypy>=1.5.0",
            "black>=23.0.0",
        ],
        "cloud": [
            "boto3>=1.28.0",
            "azure-identity>=1.14.0",
            "google-auth>=2.23.0",
            "pygithub>=1.59.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ark=ark.cli:main",
            "arkkeeper=ark.cli:main",
        ],
    },
)
