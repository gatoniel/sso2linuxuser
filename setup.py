import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = []
with open('requirements.txt') as f:
    for line in f.readlines():
        req = line.strip()
        if not req or req.startswith('#') or '://' in req:
            continue
        install_requires.append(req)

setuptools.setup(
    name="sso2linuxuser", # Replace with your own username
    version="0.0.3-dev",
    author="Niklas Netter",
    author_email="niknett@gmail.com",
    description="Use SSO to create a linux user on server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gatoniel/sso2linuxuser",
    packages=setuptools.find_packages(),
    include_package_data=True,
    license="BSD",
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    project_urls={
        'Documentation': 'https://github.com/gatoniel/sso2linuxuser',
        'Source': 'https://github.com/gatoniel/sso2linuxuser',
        'Tracker': 'https://github.com/gatoniel/sso2linuxuser/issues',
    },
    entry_points={
        'console_scripts': [
            'sso2linuxuser = sso2linuxuser.service:main',
        ],
    },
    platforms="Linux",
    python_requires='>=3.5',
    install_requires=install_requires,
)