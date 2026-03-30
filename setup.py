"""GetNexova setup configuration."""

from setuptools import setup, find_packages

setup(
    name="getnexova",
    version="4.0.0",
    description="AI-Powered Bug Bounty Automation Platform",
    author="GetNexova Team",
    url="https://github.com/lord10110/GetNexova",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "litellm>=1.40.0",
        "PyYAML>=6.0",
        "aiohttp>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "nexova=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
