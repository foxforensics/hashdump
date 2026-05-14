# Hashdump
Dump password hashes and data from an offline Active Directory database.

```console
go install go.foxforensics.dev/hashdump@latest
```

## Usage
```console
$ hashdump [-c|u] NTDS SYSTEM
```

### Options
* `-c` Dump all computers
* `-u` Dump all users

## License
Released under the [MIT License](LICENSE.md).