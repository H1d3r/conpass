# ConPass

[![PyPI version](https://badge.fury.io/py/conpass.svg)](https://pypi.org/project/conpass)
[![PyPI Statistics](https://img.shields.io/pypi/dm/conpass.svg)](https://pypistats.org/packages/conpass)
[![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

Python tool for continuous password spraying taking into account the password policy.

## Associated Blogposts
* English: https://en.hackndo.com/password-spraying-lockout/
* French: https://www.login-securite.com/blog/spray-passwords-avoid-lockouts

## Warning

Although this tool implements robust thread-safe anti-lockout protection, there can still be edge cases where accounts might be locked out. Always use with caution in production environments.

## Installation

**conpass** works with python >= 3.10

### From source

```bash
cd conpass
pipx install .
```

## Usage

**conpass** will get all domain users and try a list of passwords provided in a password file. When a user can be locked out, the tool will wait for the lockout reset period before trying another password.

```bash
conpass -d domain.local -u pixis -p P4ssw0rd -P /tmp/passwords.txt
```

All passwords provided in `/tmp/passwords.txt` will be added to a testing Queue, and will be tested against all users, whenever it is possible without locking users out.

### Security Threshold

The security threshold (`-s`, default: 2) provides a safety margin before the lockout threshold. For example:
- Lockout threshold: 5
- Security threshold: 2
- Maximum tests per user: 3

This accounts for potential concurrent authentications from the user or other tools.

## License

MIT
