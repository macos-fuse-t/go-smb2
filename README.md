# Lightweight SMB2/3 server

## Introduction

I started this project to enable Time Machine backups over the network for my Mac. My primary focus was ensuring compatibility with macOS clients. Therefore, I've implemented many macOS-specific features, including extended attribute support, unix file modes, bonjour advertisement, and other proprietary Apple extensions. Because of this, other operating systems may not fully work or require additional features.

The project is designed to serve as a library for implementing custom file systems. This means it can either substitute libfuse or be integrated into bigger projects. The file system interface is in vfs/vfs.go. I provided an example of a passthrough file system implementation.

Keep in mind, there are certain features, such as parallel connection support, file locking, user authentication, and impersonation, which are either in their early stages or not yet implemented, primarily due to my limited focus.

This project is dual licensed:
AGPL or proprietary commercial license

For inquiries about a proprietary license or for support, please contact me at alex@fuse-t.org.


## Build:
```
go mod tidy
go build
```
## Run:
```
./go-smb2 [-g] [-l listen_address] [-m mount_dir]
```
