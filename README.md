# pyshell

A python implementation of shell servers

## TCP Shell

The only type of shell currently supported by this project.

### Usage

Unix:
```bash
export PORT=8022
./tcp_shell.sh
```

Windows:
```bash
set PORT=8022
./tcp_shell.sh
```

You may supply the program parameters as environment variables.
The supported parameters are:

| Variable Name | Description |
| -------- | -------- |
| ADDRESS | Address to bind socket to |
| PORT | Port number to listen on |
| SILENT | Supply any value to disable logging |
| LOG_LEVEL | Log level output |
| LOG_FILE | Log also to supplied path |
