defmodule TinyAESTest do
  use ExUnit.Case

  setup do
    key = :crypto.strong_rand_bytes(32) |> Base.encode64()
    System.put_env("ENCRYPTION_KEY", key)
    :ok
  end

  test "encrypts and decrypts plaintext" do
    plaintext = "Hello, world!"
    aad = "test_aad"
    ciphertext = TinyAES.encrypt(plaintext, aad)
    assert {:ok, decrypted} = TinyAES.decrypt(ciphertext, aad)
    assert decrypted == plaintext
  end

  test "decrypts invalid ciphertext" do
    assert TinyAES.decrypt("not a binary") ==
             {:error, "Ciphertext must be a binary with at least 32 bytes"}

    assert TinyAES.decrypt(<<0::128>>) ==
             {:error, "Ciphertext must be a binary with at least 32 bytes"}
  end

  test "generates valid key" do
    key = TinyAES.generate_key_env()
    assert {:ok, decoded} = Base.decode64(key)
    assert byte_size(decoded) == 32
  end

  test "puts generates valid key" do
    assert :ok = TinyAES.puts_generate_key_env()
  end

  test "handles missing encryption key" do
    System.delete_env("ENCRYPTION_KEY")

    assert TinyAES.encrypt("test") ==
             {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}

    assert TinyAES.decrypt(<<0::256>>) ==
             {:error, "Encryption key not found in environment variable ENCRYPTION_KEY"}
  end

  test "handles invalid encryption key" do
    System.put_env("ENCRYPTION_KEY", "invalid")

    assert TinyAES.encrypt("test") ==
             {:error, "Invalid encryption key: must be a 32-byte base64-encoded string"}

    assert TinyAES.decrypt(<<0::256>>) ==
             {:error, "Invalid encryption key: must be a 32-byte base64-encoded string"}
  end
end
