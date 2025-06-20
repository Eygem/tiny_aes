# TinyAES

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Eygem/tiny_aes/blob/main/LICENSE)
[![Build Status](https://github.com/Eygem/tiny_aes/actions/workflows/ci.yml/badge.svg)](https://github.com/Eygem/tiny_aes/actions)

**TinyAES** is a lightweight, dependency-free Elixir wrapper for AES-256-GCM encryption and decryption using Erlang's `:crypto` module. It provides robust error handling, support for Additional Authenticated Data (AAD), and a simple API. The encryption key is securely retrieved from the `ENCRYPTION_KEY` environment variable.

## Features
- **Lightweight**: Less than 50 lines of core code.
- **Dependency-Free**: Relies only on Erlang's `:crypto` module.
- **Robust Error Handling**: Covers returned `:error`, raised `{etag, reason, stack}` exceptions, and key validation errors.
- **AES-256-GCM**: Secure, authenticated encryption with 16-byte IV and tag.
- **AAD Support**: Optional Additional Authenticated Data for enhanced security.
- **Key Management**: Environment-based key retrieval with Base64 encoding.
- **3-tuples Compatible**: Handles the latest `:crypto` exception format introduced with Erlang OTP 25.

## Installation

Add **TinyAES** to your `mix.exs` dependencies:
```elixir
{:tiny_aes, "~> 0.1"}
```
Run `mix deps.get` to fetch the dependency.

## Setup

Generate a 32-byte encryption key, and add it to your `.env` file:
```bash
mix run -e 'TinyAES.puts_generate_key_env()'
# Copy the output to .env:
ENCRYPTION_KEY=your_base64_encoded_key_here
```
The function outputs a base64-encoded key, e.g., `OuaO+dtNNgxJjQLGHMLJ9m8rSQDsVdqkGrf7ySSj3Yg=`. Add the key to your `.env` file:

Ensure the `ENCRYPTION_KEY` environment variable is set in your application (e.g., using [`env_loader`](https://github.com/Eygem/env_loader) or [`dotenv`](https://github.com/avdi/dotenv_elixir)).

## Usage

Encrypt and decrypt data without optional AAD::
```elixir
# Encrypt a message
plaintext = "Sensitive data"
ciphertext = TinyAES.encrypt(plaintext)

# Decrypt it
{:ok, decrypted} = TinyAES.decrypt(ciphertext)
assert decrypted == plaintext
```

Encrypt and decrypt data with optional AAD (e.g., user or session ID)
```elixir
# Encrypt a message
plaintext = "Sensitive data"
ciphertext = TinyAES.encrypt(plaintext, "optional_aad")

# Decrypt it
{:ok, decrypted} = TinyAES.decrypt(ciphertext, "optional_aad")
assert decrypted == plaintext
```

Handle edge cases:
```elixir
# Handle invalid input
TinyAES.decrypt("not a binary")
# {:error, "Ciphertext must be a binary with at least 32 bytes"}

# Handle missing key
System.delete_env("ENCRYPTION_KEY")
TinyAES.encrypt("test")
# {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}
```

## API

- `TinyAES.encrypt(plaintext, aad \\ "")`:
    - Encrypts plaintext, returning `<<iv::binary-16, tag::binary-16, ciphertext::binary>>` or `{:error, reason}`.
- `TinyAES.decrypt(ciphertext, aad \\ "")`:
    - Decrypts ciphertext, returning `{:ok, plaintext}` or `{:error, reason}`.
- `TinyAES.puts_generate_key_env()`:
    - Generates, prints, and returns `:ok` for a Base64-encoded 32-byte key.
- `TinyAES.generate_key_env()`:
    - Generates a Base64-encoded 32-byte key.
- `TinyAES.get_key_env()`:
    - Retrieves and decodes the key from `ENCRYPTION_KEY` returning `{:ok, key}` or `{:error, reason}`.



See [HexDocs](https://hex.pm/packages/tiny_aes) for full documentation.


## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/Eygem/tiny_aes). For major changes, discuss them in an issue first. Ensure tests pass with `mix test`.


## License

Released under the MIT License. See the **[LICENSE](https://github.com/Eygem/tiny_aes/blob/main/LICENSE)** file for details.


## Acknowledgments

Developed with the help of Grok, created by xAI. Thanks to Erlang's `:crypto` for providing a solid foundation.


