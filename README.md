# Pallas

Resign Arma 3 Mods

## Usage

```bash
pallas src
```

Call `pallas` with the path to the source directory, which contains all of your `@` mods. Pallas will resign each mod with its own temporary private key. EBOs and their keys will be left untouched.

New .bisign files are only created when the mod has been modified since the last time it was signed, making updates with tools like Swifty easy.

[pallas.webm](https://github.com/user-attachments/assets/6b071446-8ca3-45c4-8c99-ab33fe75b59b)
