![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Greenbone Vulnerability Manager <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release/greenbone/gvmd.svg)](https://github.com/greenbone/gvmd/releases)
[![Build and Test](https://github.com/greenbone/gvmd/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/greenbone/gvmd/actions/workflows/build-and-test.yml)

The Greenbone Vulnerability Manager is the central management service between
security scanners and the user clients.

It manages the storage of any vulnerability management configurations and of the
scan results. Access to data, control commands and workflows is offered via the
XML-based Greenbone Management Protocol (GMP). Controlling scanners like
the [OPENVAS Scanner](https://github.com/greenbone/openvas-scanner)* is done via
the Open Scanner Protocol (OSP).

- [Releases](#releases)
- [Installation and Usage](#installation-and-usage)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
  - [Code style and formatting](#code-style-and-formatting)
  - [CMake formatting](#cmake-formatting)
- [License](#license)

## Releases

All [release files](https://github.com/greenbone/gvmd/releases) are signed with
the [Greenbone Community Feed integrity key](https://community.greenbone.net/t/gcf-managing-the-digital-signatures/101).
This gpg key can be downloaded at https://www.greenbone.net/GBCommunitySigningKey.asc
and the fingerprint is `8AE4 BE42 9B60 A59B 311C  2E73 9823 FAA6 0ED1 E580`.

## Installation and Usage

This module can be configured, built and installed with following commands:

```sh
cmake .
make install
```

For detailed installation requirements and instructions, please see the file
[INSTALL.md](INSTALL.md). The file also contains instructions for setting up
`gvmd` and for connecting `gvmd` to vulnerability scanners and to the
*[GSA](https://github.com/greenbone/gsa)* web interface.

In case everything was installed using the defaults, then starting the manager
daemon can be done with this simple command:

```sh
gvmd
```

To see all available command line options of gvmd enter this command:

```sh
gvmd --help
```

If you are not familiar or comfortable building from source code, we recommend
that you use the Greenbone Enterprise TRIAL, a prepared virtual
machine with a readily available setup. Information regarding the virtual machine
is available at <https://www.greenbone.net/en/testnow>.

## Support

For any question on the usage of `gvmd` please use the [Greenbone Community
Forum](https://forum.greenbone.net/). If you found a problem with the
software, please [create an issue](https://github.com/greenbone/gvmd/issues) on
GitHub. If you are a Greenbone customer you may alternatively or additionally
forward your issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone AG](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/gvmd/pulls) on GitHub. Bigger changes need
to be discussed with the development team via the [issues section at
GitHub](https://github.com/greenbone/gvmd/issues) first.

### Code style and formatting

Before creating a pull request, it is recommended to run the following command:

```sh
make format
```

This reformats the new code to ensure that it follows the code style and
formatting guidelines.

### CMake formatting

All CMake files are formatted using [gersemi](https://github.com/BlankSpruce/gersemi).
To install gersemi on a Debian based system the following commands can be used:

```sh
sudo apt install pipx
pipx install gersemi
```

To format all CMake files run the command:

```sh
gersemi -i cmake .
```

## License

Copyright (C) 2009-2025 [Greenbone AG](https://www.greenbone.net/)

Licensed under the [GNU Affero General Public License v3.0 or later](COPYING).
