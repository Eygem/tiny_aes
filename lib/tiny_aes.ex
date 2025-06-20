defmodule TinyAES do
  @moduledoc """
  TinyAES is a lightweight, dependency-free Elixir wrapper for AES-256-GCM encryption and decryption
  using Erlang's `:crypto` module. It provides robust error handling, support for Additional
  Authenticated Data (AAD), and a simple API. The encryption key is securely retrieved from
  the `ENCRYPTION_KEY` environment variable.

  ## Features
  - **Lightweight**: Less than 50 lines of core code.
  - **Dependency-Free**: Relies only on Erlang's `:crypto` module.
  - **Robust Error Handling**: Covers returned `:error`, raised `{etag, reason, stack}` exceptions, and key validation errors.
  - **AES-256-GCM**: Secure, authenticated encryption with 16-byte IV and tag.
  - **AAD Support**: Optional Additional Authenticated Data for enhanced security.
  - **Key Management**: Environment-based key retrieval with Base64 encoding.
  - **3-tuples Compatible**: Handles the latest `:crypto` exceptions formats

  ## Setup
  Generate a 32-byte encryption key, and add it to your `.env` file:
  ```bash
  mix run -e 'TinyAES.puts_generate_key_env()'
  # Copy the output to .env:
  ENCRYPTION_KEY=your_base64_encoded_key_here
  ```
  Add the output to your `.env` file as `ENCRYPTION_KEY=your_base64_encoded_key_here`.
  Ensure the `ENCRYPTION_KEY` environment variable is set in your application.

  ## Usage
  ```elixir
  plaintext = "Hello, world!"
  ciphertext = TinyAES.encrypt(plaintext, "optional_aad")
  {:ok, decrypted} = TinyAES.decrypt(ciphertext, "optional_aad")
  # decrypted == "Hello, world!"
  ```

  ## Security Notes
  Uses :crypto.strong_rand_bytes/1 for cryptographically secure IV and key generation.
  Requires a 32-byte key, base64-encoded in the ENCRYPTION_KEY environment variable.
  Always use the same AAD for encryption and decryption to ensure successful authentication.
  """

  @doc """
  Encrypts plaintext using AES-256-GCM, returning a binary containing the IV, tag, and ciphertext.
  Optionally accepts Additional Authenticated Data (AAD) for enhanced security. The plaintext is converted
  to a binary with `to_string/1`. Uses a 32-byte key from `get_key_env/0` and a random 16-byte IV.

  ## Parameters
  - plaintext: The data to encrypt (string or binary).
  - aad: Additional Authenticated Data (string or binary, optional, defaults to `""`).

  ## Returns
  - `binary()`: `<<iv::binary-16, tag::binary-16, ciphertext::binary>>` on success.
  - `{:error, String.t()}`: If the encryption key is invalid.

  ## Examples
      iex> ciphertext = TinyAES.encrypt("Hello, world!")
      iex> byte_size(ciphertext) >= 32
      true

      iex> ciphertext = TinyAES.encrypt("data", "aad")
      iex> {:ok, "data"} = TinyAES.decrypt(ciphertext, "aad")

      iex> System.delete_env("ENCRYPTION_KEY")
      iex> TinyAES.encrypt("test")
      {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}
  """
  def encrypt(plaintext, aad \\ "") do
    # Get the encryption key
    case get_key_env() do
      {:ok, key} ->
        # Create random Initialisation Vector (IV) using Erlang OTP :cripto.strong_rand_bytes(N :: integer() >= 0) -> binary()
        # Generates N bytes randomly uniform 0..255, and returns the result in a binary
        # Uses a cryptographically secure prng seeded and periodically mixed with operating system provided entropy
        # By default this is the RAND_bytes method from OpenSSL
        iv = :crypto.strong_rand_bytes(16)
        # Perform encryption with AEAD (Authenticated Encryption with Associated Data)
        # :aes_256_gcm: AES with a 256-bit key in GCM mode
        # key: The encryption key
        # iv: Initialization Vector
        # encrypted_data: The actual encrypted content
        # @aad: Additional Authenticated Data (can be empty binary if not used)
        # tag: The authentication tag to verify data integrity and authenticity
        # true: Decrypt flag (true for encrypt, false for decrypt)
        {ciphertext, tag} =
          :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, to_string(plaintext), aad, true)

        # Concatenates the IV, tag, and ciphertext into a single binary for storage
        iv <> tag <> ciphertext

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Decrypts AES-256-GCM ciphertext with robust error handling.
  Expects a binary ciphertext containing a 16-byte IV, a 16-byte tag, and the encrypted data.
  Optionally accepts Additional Authenticated Data (AAD) matching the encryption AAD.
  Uses the key from `get_key_env/0`.
  Returns `{:ok, plaintext}` on success or `{:error, reason}` on failure, handling:
  - Invalid ciphertext format (e.g., too short).
  - Failed tag verification (`:error`).
  - Invalid arguments (e.g., wrong key size, raised as {`badarg, reason, stack`}).
  - Invalid or missing encryption key.
  - Unexpected errors.

  ## Parameters
  - `ciphertext`: Binary containing `<<iv::binary-16, tag::binary-16, encrypted_data::binary>>`.
  - `aad`: Additional Authenticated Data used during encryption (string or binary, optional, defaults to `""`).

  ## Examples
      iex> ciphertext = TinyAES.encrypt("Hello, world!")
      iex> TinyAES.decrypt(ciphertext)
      {:ok, "Hello, World!"}

      iex> TinyAES.decrypt(encrypted, "wrong_aad")
      {:error, "Decryption failed: unknown error"}

      iex> TinyAES.decrypt(<<0::128>>)
      {:error, "Ciphertext must be a binary with at least 32 bytes"}

      iex> TinyAES.decrypt("not a binary")
      {:error, "Ciphertext must be a binary with at least 32 bytes"}

      iex> System.delete_env("ENCRYPTION_KEY")
      iex> TinyAES.decrypt(TinyAES.encrypt("test"))
      {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}
  """
  def decrypt(ciphertext, aad \\ "")

  def decrypt(ciphertext, aad) when is_binary(ciphertext) and byte_size(ciphertext) >= 32 do
    # Get the encryption key
    case get_key_env() do
      {:ok, key} ->
        try do
          # def decrypt(ciphertext) do
          # Extract Initialization Vector (IV) and Tag from ciphertext
          # IV: 16 bytes for AES GCM
          # Tag: 16 bytes for AES GCM authentication tag
          <<iv::binary-16, tag::binary-16, encrypted_data::binary>> = ciphertext
          # Perform decryption with AEAD (Authenticated Encryption with Associated Data)
          # :aes_256_gcm: AES with a 256-bit key in GCM mode
          # key: The encryption key
          # iv: Initialization Vector
          # encrypted_data: The actual encrypted content
          # @aad: Additional Authenticated Data (can be empty binary if not used)
          # tag: The authentication tag to verify data integrity and authenticity
          # false: Decrypt flag (true for encrypt, false for decrypt)
          # It returns :error if tag verification fails
          # It raises an ErlangError (badarg, etc.) for invalid arguments or internal issues
          case :crypto.crypto_one_time_aead(
                 :aes_256_gcm,
                 key,
                 iv,
                 encrypted_data,
                 aad,
                 tag,
                 false
               ) do
            plaintext when is_binary(plaintext) ->
              # Successfully decrypted and authenticated
              {:ok, plaintext}

            :error ->
              # This indicates a failed authentication tag verification
              {:error, "Decryption failed: unknown error"}
          end
        rescue
          MatchError ->
            # Catches if the initial binary pattern match fails (e.g., ciphertext too short)
            {:error,
             "Invalid ciphertext format: It must contain at least a 16-byte IV and 16-byte Tag"}

          e in ErlangError ->
            case e.original do
              {etag, reason, stack} ->
                # Catches ErlangError 3-tuples new style messages: error:{Tag, C_FileInfo, Description}
                # Exception tags are
                # badarg - one or more arguments are of wrong data type or are otherwise badly formed
                # notsup - algorithm is known but not supported by libcrypto or explicitly disabled
                # error - an error condition that should not occur, for example a memory allocation failed
                {:error,
                 "Decryption failed: #{inspect(etag)}, #{inspect(reason)}, #{inspect(stack)}"}

              other ->
                # # Catches any other unexpected Elixir exceptions
                {:error, "Decryption failed: unexpected error #{inspect(other)}"}
            end
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def decrypt(_, _), do: {:error, "Ciphertext must be a binary with at least 32 bytes"}

  @doc """
  Generates a secure 32-byte key and convert it to a Base64-encoded string for use in `.env` files.
  Use this to create a key for the `ENCRYPTION_KEY` environment variable. See `puts_generate_key_env/0`
  to print the key directly.

  ## Returns
  - a Base64-encoded string.

  ## Examples
      iex> key = TinyAES.generate_key_env()
      iex> String.length(key) > 0
      true

      iex> {:ok, decoded} = Base.decode64(TinyAES.generate_key_env())
      iex> byte_size(decoded)
      32
  """
  def generate_key_env do
    :crypto.strong_rand_bytes(32) |> Base.encode64()
  end

  @doc """
  Generates a secure 32-byte key, prints it as a Base64-encoded string for use in `.env` files, and returns `:ok`.
  Add the output to your `.env` or `.env.dev` file as `ENCRYPTION_KEY=your_base64_encoded_key_here`.

  ## Returns
  - `:ok`

  ## Examples
      iex> TinyAES.puts_generate_key_env()
      # Prints: "PNu96VvFplhWeR/ojYPtDHiTgAdGxjPs9NGKl0Zn3fA=" (example; actual key is random)
      :ok
  """
  def puts_generate_key_env do
    generate_key_env() |> IO.puts()
    :ok
  end

  @doc """
  Retrieves and decodes a 32-byte encryption key from the `ENCRYPTION_KEY` environment variable.
  The key must be a Base64-encoded 32-byte string.

  ## Returns
  - `{:ok, binary()}`: A 32-byte binary key on success.
  - `{:error, String.t()}`: An error if:
    - `ENCRYPTION_KEY` is not set.
    - The key is not a valid 32-byte Base64-encoded string.

  ## Examples
      iex> System.put_env("ENCRYPTION_KEY", TinyAES.generate_key_env())
      iex> {:ok, key} = TinyAES.get_key_env()
      iex> byte_size(key)
      32

      iex> System.delete_env("ENCRYPTION_KEY")
      iex> TinyAES.get_key_env()
      {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}

      iex> System.put_env("ENCRYPTION_KEY", "invalid")
      iex> TinyAES.get_key_env()
      {:error, "Invalid encryption key: must be a 32-byte base64-encoded string"}
  """
  def get_key_env do
    case System.get_env("ENCRYPTION_KEY") do
      nil ->
        {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}

      key ->
        case Base.decode64(key) do
          {:ok, decoded_key} when byte_size(decoded_key) == 32 ->
            {:ok, decoded_key}

          _ ->
            {:error, "Invalid encryption key: must be a 32-byte base64-encoded string"}
        end
    end
  end
end
