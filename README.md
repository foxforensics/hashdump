# Hashdump
Dump password hashes and records from an offline Active Directory database.

```console
go install go.foxforensics.dev/hashdump@latest
```

## Usage
```console
$ hashdump [-ugc] NTDS SYSTEM
```

### Options
* `-u` Dump all users
* `-g` Dump all groups
* `-c` Dump all computers

## License
Released under the [MIT License](LICENSE.md).