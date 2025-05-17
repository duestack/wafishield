from setuptools import setup, find_packages
import os

# Read the README.md file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read() if os.path.exists("README.md") else ""

# Replace relative image paths with absolute URLs for PyPI
if os.path.exists("README.md"):
    # Replace local image reference with a GitHub raw URL
    long_description = long_description.replace(
        'src="assets/logo.png"',
        'src="https://raw.githubusercontent.com/duestack/wafishield/main/assets/logo.png"',
    )

# Define package dependencies
install_requires = [
    "pyyaml>=6.0",
    "regex>=2021.8.3",
    "jsonschema>=4.0.0",
    "requests>=2.25.0",
]

# Optional dependencies
extras_require = {
    "openai": ["openai>=0.27.0"],
    "anthropic": ["anthropic>=0.2.0"],
    "nlp": ["nltk>=3.6.0", "spacy>=3.0.0"],
    "observability": [
        "opentelemetry-api>=1.0.0",
        "opentelemetry-sdk>=1.0.0",
        "opentelemetry-exporter-otlp>=1.0.0",
    ],
    "dev": [
        "pytest>=6.0.0",
        "pytest-cov>=2.12.0",
        "black>=21.5b2",
        "isort>=5.9.0",
        "mypy>=0.900",
    ],
    "api": ["fastapi>=0.68.0", "uvicorn>=0.15.0", "pydantic>=1.8.2"],
    "all": [
        "openai>=0.27.0",
        "anthropic>=0.2.0",
        "nltk>=3.6.0",
        "spacy>=3.0.0",
        "opentelemetry-api>=1.0.0",
        "opentelemetry-sdk>=1.0.0",
        "opentelemetry-exporter-otlp>=1.0.0",
        "fastapi>=0.68.0",
        "uvicorn>=0.15.0",
        "pydantic>=1.8.2",
    ],
}

setup(
    name="wafishield",
    version="0.1.1",
    author="duestack",
    author_email="info@duestack.com",
    description="A two-layer, fully-extensible Python package for protecting LLM/agent apps against OWASP Top 10 and other evolving LLM vulnerabilities.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/duestack/wafishield",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=install_requires,
    extras_require=extras_require,
    include_package_data=True,
    package_data={
        "wafishield": ["rules/*.yml", "patterns/*.yml", "schemas/*.json"],
    },
)
