defmodule Ueberauth.Strategy.PlanGrid do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with PlanGrid.

  ### Setup

  Create an application in PlanGrid for you to use.
  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          plangrid: { Ueberauth.Strategy.PlanGrid, [] }
        ]

  Then include the configuration for PlanGrid.

      config :ueberauth, Ueberauth.Strategy.PlanGrid.OAuth,
        client_id: System.get_env("PLANGRID_CLIENT_ID"),
        client_secret: System.get_env("PLANGRID_CLIENT_SECRET")

  """
  use Ueberauth.Strategy, oauth2_module: Ueberauth.Strategy.PlanGrid.OAuth

  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.Helpers

  @doc """
  Handles the initial redirect to the PlanGrid authentication page.
  """
  def handle_request!(conn) do
    opts = [redirect_uri: redirect_uri(conn)]
    module = option(conn, :oauth2_module)
    Helpers.redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from PlanGrid. When there is a failure from PlanGrid the
  failure is included in the `ueberauth_failure` struct. Otherwise the
  information returned from PlanGrid is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code, redirect_uri: redirect_uri(conn)]])

    if token.access_token == nil do
      Helpers.set_errors!(conn, [
        error(
          token.other_params["error"],
          token.other_params["error_description"]
        )
      ])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw PlanGrid
  response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:plangrid_user, nil)
    |> put_private(:plangrid_token, nil)
  end

  @doc """
  Fetches the uid field from the PlanGrid response. This is the id field for
  the user.
  """
  def uid(conn) do
    conn.private.plangrid_user["id"]
  end

  @doc """
  Includes the credentials from the PlanGrid response.
  """
  def credentials(conn) do
    token = conn.private.plangrid_token

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth`
  struct.
  """
  def info(conn) do
    user = conn.private.plangrid_user

    %Info{
      name: "#{user["first_name"]} #{user["last_name"]}",
      first_name: user["first_name"],
      last_name: user["last_name"],
      email: user["email_address"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the PlanGrid
  callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.plangrid_token,
        user: conn.private.plangrid_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :plangrid_token, token)

    with {:ok, user} <- get_me(token) do
      put_private(conn, :plangrid_user, user)
    else
      {:error, :unauthorized} -> set_errors!(conn, [error("token", "unauthorized")])
      {:error, %OAuth2.Error{reason: reason}} -> set_errors!(conn, [error("OAuth2", reason)])
      {:error, reason} -> set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(Helpers.options(conn), key, Keyword.get(default_options(), key))
  end

  defp redirect_uri(conn) do
    Helpers.callback_url(conn)
  end

  defp get_me(token) do
    headers = [{"accept", "application/vnd.plangrid+json; version=1"}]

    case Ueberauth.Strategy.PlanGrid.OAuth.get(token, "/me", headers) do
      {:ok, %OAuth2.Response{status_code: 200, body: me}} -> {:ok, me}
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} -> {:error, :unauthorized}
      _other -> {:error, :no_user}
    end
  end
end
