defmodule RtpEngineClient.Mixfile do
  use Mix.Project

  def project do
    [app: :rtpengineclient,
     version: "0.1.5",
     elixir: "~> 1.4",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps(),
     description: description(),
     package: package()]
  end

  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [extra_applications: [:logger]]
  end

  defp deps do
    [{:dialyxir, "~> 0.5", only: [:dev], runtime: false},
     {:ex_doc, "~> 0.14", only: :dev, runtime: false},
     {:socket, "~> 0.3.5"},
     {:bento, "~> 0.9.2"}]
  end

  defp description do
    """
    An Elixir client for the Sipwise NGCP RtpEngine proxy.
    """
  end

  defp package do
    [# These are the default files included in the package
     name: :rtpengineclient,
     files: ["lib", "mix.exs", "README.md", "LICENSE"],
     maintainers: ["Guilherme Balena Versiani"],
     licenses: ["BSD"],
     links: %{"GitHub" => "https://github.com/balena/elixir-rtpengine"}]
  end
end
