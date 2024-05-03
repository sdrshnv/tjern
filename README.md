https://github.com/sudarshanvankudre/tjern/assets/20431892/a9d299b5-59b7-4cd3-af00-2858a3541101


# tjern
`tjern` is a minimal command line journaling application. Entries are end-to-end encrypted by default and synced to the cloud, for peace of mind, wherever you are. 

## Install
### Homebrew
```
brew tap sudarshanvankudre/tjern https://github.com/sudarshanvankudre/tjern.git
```
```
brew install sudarshanvankudre/tjern/tjern
```
### If you have Go installed
```
go install github.com/sudarshanvankudre/tjern@latest
```
Make sure the path to the tjern binary is included on your PATH environment variable.

## Usage
```
tjern
```
On your first usage, you'll need to create an account and enter credentials, but afterwards, you won't need to enter them again.

After your credentials are saved, you can quickly create an entry without going through the UI.
```
tjern -n This is a new entry without going through the UI.
```

## Feedback
Feedback/bug reports are appreciated! Please open issues as needed.
