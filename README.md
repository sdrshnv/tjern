![Tjern Demo 2 Gif](https://github.com/sudarshanvankudre/tjern/assets/20431892/5b79574e-3f0d-48ec-928f-0dfa46eca347)

# tjern
`tjern` is a minimal command line journaling application. Entries are end-to-end encrypted by default and synced to the cloud, for peace of mind, wherever you are. 

## Install
### Homebrew
```
brew tap sdrshnv/tjern https://github.com/sdrshnv/tjern.git
```
```
brew install sdrshnv/tjern/tjern
```

## Usage
```
tjern
```
On your first usage, you'll need to create an account and enter credentials, but afterwards, you won't need to enter them again.

### After your credentials are saved
Quickly create an entry without going through the UI.
```
tjern -n This is a new entry without going through the UI.
```

Export your entries to your machine.
```
tjern -export
```

Display all the options
```
tjern -help
```

## Feedback
Feedback/bug reports are appreciated! Please open issues as needed.
