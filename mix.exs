defmodule BlockScanners.MixProject do
  use Mix.Project

  def project do
    [
      app: :block_scanners,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Plug that blocks vulnerability scanner traffic (WordPress, PHP, etc.) early in the endpoint pipeline."
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.14"}
    ]
  end
end
