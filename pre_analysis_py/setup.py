import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="native_summary",
    version="0.0.1",
    author="NativeSummary",
    author_email="NativeSummary@github.com",
    description="Static analysis for Android JNI functions.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NativeSummary/pre_analysis_py",
    project_urls={
        "Bug Tracker": "https://github.com/NativeSummary/pre_analysis_py/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.8", # for `:=`
)