defmodule PlugDeflect do
  @moduledoc """
  Plug that deflects invalid traffic early in the endpoint pipeline.

  Matches on file extensions (.php, .asp, .env, etc.), known non-Elixir paths
  (wp-admin, xmlrpc, phpmyadmin, etc.), and path traversal attempts.
  Returns 404 immediately without hitting the router.

  ## Usage

  Add to your endpoint.ex after `Plug.RequestId`:

      plug Plug.RequestId
      plug PlugDeflect
      plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  """

  import Plug.Conn
  require Logger

  @blocked_extensions ~w(
    .7z
    .asp
    .aspx
    .bak
    .cfg
    .cgi
    .conf
    .dist
    .env
    .gz
    .ini
    .jsp
    .log
    .old
    .orig
    .phar
    .php
    .php3
    .php4
    .php5
    .php7
    .phtml
    .rar
    .save
    .sql
    .swp
    .tar.gz
    .tmp
    .xml
    .yaml
    .yml
    .zip
  )

  @blocked_paths ~w(
    /wp-admin /wp-content /wp-includes /wp-login /wp-json /wp-cron
    /wordpress /xmlrpc /wp-config /wp-settings

    /drupal /sites/default /misc/drupal
    /administrator /joomla
    /magento /downloader /skin/adminhtml

    /vendor/phpunit /vendor/composer
    /phpmyadmin /pma /myadmin /adminer
    /info.php /phpinfo.php /test.php /shell.php /cmd.php /eval-stdin.php

    /telescope /nova /horizon /_ignition
    /node_modules /npm-debug /package.json /package-lock.json /yarn.lock
    /static/admin /django
    /manager/html /host-manager
    /jenkins /jenkins/script
    /grafana
    /actuator /actuator/health /actuator/env /actuator/info
    /api-docs /swagger /swagger-ui
    /solr /solr/admin
    /elmah.axd /trace.axd /web.config

    /ckeditor /fckeditor /tiny_mce /kcfinder

    /config.bak /backup /database
    /dump /db.sql /backup.sql /data.sql

    /.git /.svn /.env /.htaccess /.htpasswd
    /.aws /.docker /.kube /.ssh /.bash_history
    /.DS_Store /.vscode /.idea
    /.well-known/security.txt

    /server-status /server-info
    /cgi-bin
    /autodiscover /owa /exchange /ecp
  )

  def init(opts), do: opts

  def call(conn, _opts) do
    path = conn.request_path |> String.downcase()
    decoded_path = fully_decode(path)

    cond do
      path_traversal?(decoded_path) ->
        deflect(conn, path)

      blocked_extension?(decoded_path) ->
        deflect(conn, path)

      blocked_path?(decoded_path) ->
        deflect(conn, path)

      true ->
        conn
    end
  end

  defp fully_decode(path) do
    decoded = URI.decode(path)

    if decoded == path do
      path
    else
      fully_decode(decoded)
    end
  end

  defp path_traversal?(path) do
    String.contains?(path, "..")
  end

  defp blocked_extension?(path) do
    Enum.any?(@blocked_extensions, &String.ends_with?(path, &1))
  end

  defp blocked_path?(path) do
    Enum.any?(@blocked_paths, &String.starts_with?(path, &1))
  end

  defp deflect(conn, path) do
    Logger.warning("Deflected: #{conn.method} #{path} from #{peer_ip(conn)}")

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(404, "")
    |> halt()
  end

  defp peer_ip(conn) do
    %{address: addr} = Plug.Conn.get_peer_data(conn)
    :inet.ntoa(addr) |> to_string()
  end
end
