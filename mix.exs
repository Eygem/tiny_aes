defmodule TinyAES.MixProject do
  use Mix.Project

  def project do
    [
      app: :tiny_aes,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      description:
        "A lightweight, dependency-free Elixir wrapper for AES-256-GCM encryption and decryption with AAD support, robust error handling and simple API. The encryption key is securely retrieved from the ENCRYPTION_KEY environment variable.",
      package: package(),
      deps: deps(),
      name: "TinyAES",
      source_url: "https://github.com/eygem/tiny_aes",
      docs: [
        main: "TinyAES",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/eygem/tiny_aes"}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # For generating docs
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end
end
