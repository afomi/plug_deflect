defmodule BlockScanners do
  @moduledoc """
  Plug that blocks common vulnerability scanner requests early in the endpoint pipeline.

  Matches on file extensions (.php, .asp, .env, etc.) and known scanner paths
  (wp-admin, xmlrpc, phpmyadmin, etc.). Returns 404 immediately without hitting
  the router.

  ## Usage

  Add to your endpoint.ex after `Plug.RequestId`:

      plug Plug.RequestId
      plug BlockScanners
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
    .php
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
    /wordpress /xmlrpc /xmlrpc.php

    /drupal /sites/default /misc/drupal
    /administrator /joomla
    /magento /downloader /skin/adminhtml

    /vendor/phpunit /phpmyadmin /pma /myadmin /adminer

    /telescope /nova /horizon /_ignition
    /node_modules /npm-debug /package.json /package-lock.json /yarn.lock
    /admin/login /static/admin /django
    /manager /host-manager /manager/html /status
    /jenkins /script /jenkins/script
    /grafana
    /actuator /actuator/health /actuator/env /actuator/info
    /api-docs /swagger /swagger-ui
    /solr /solr/admin
    /console /debug /elmah.axd /trace.axd /web.config

    /config.bak /backup /db /database
    /dump /db.sql /backup.sql /data.sql

    /.git /.svn /.env /.htaccess /.htpasswd
    /.aws /.docker /.kube /.ssh /.bash_history
    /.DS_Store /.vscode /.idea

    /server-status /server-info
    /cgi-bin /scripts
    /autodiscover /owa /exchange /ecp
    /wp-config /wp-settings
  )

  def init(opts), do: opts

  def call(conn, _opts) do
    path = conn.request_path |> String.downcase()

    cond do
      blocked_extension?(path) ->
        block(conn, path)

      blocked_path?(path) ->
        block(conn, path)

      true ->
        conn
    end
  end

  defp blocked_extension?(path) do
    Enum.any?(@blocked_extensions, &String.ends_with?(path, &1))
  end

  defp blocked_path?(path) do
    Enum.any?(@blocked_paths, &String.starts_with?(path, &1))
  end

  defp block(conn, path) do
    Logger.warning("Blocked scanner request: #{conn.method} #{path} from #{peer_ip(conn)}")

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
