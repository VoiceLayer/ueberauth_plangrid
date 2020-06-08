defmodule UeberauthPlangrid.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_plangrid,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ueberauth, "~> 0.6.0"},
      {:oauth2, "~> 1.0 or ~> 2.0"},
      {:ex_doc, "~> 0.22.1", only: :dev}
    ]
  end

  defp description do
    """
    An Ueberauth strategy for using PlanGrid (OAuth) authentication.
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENCE*"],
      maintainers: ["Gary Rennie", "Gabi Zuniga"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/voicelayer/ueberauth_plangrid",
        "Docs" => "https://hexdocs.pm/ueberauth_plangrid"
      }
    ]
  end
end
