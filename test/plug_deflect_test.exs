defmodule PlugDeflectTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog
  import Plug.Test

  defp deflected?(method \\ :get, path) do
    conn = conn(method, path) |> PlugDeflect.call([])
    {conn.status == 404, conn.halted}
  end

  # --- Path traversal ---

  test "deflects path traversal" do
    assert deflected?("/../../etc/passwd") == {true, true}
  end

  test "deflects URL-encoded path traversal" do
    assert deflected?("/%2e%2e/%2e%2e/etc/passwd") == {true, true}
  end

  test "deflects double-encoded path traversal" do
    assert deflected?("/%252e%252e/%252e%252e/etc/passwd") == {true, true}
  end

  test "deflects Windows-style path traversal" do
    assert deflected?("/..\\..\\windows\\system32") == {true, true}
  end

  # --- Extensions - original ---

  test "deflects .php requests" do
    assert deflected?("/wp-login.php") == {true, true}
  end

  test "deflects .asp requests" do
    assert deflected?("/admin.asp") == {true, true}
  end

  test "deflects .env requests" do
    assert deflected?("/.env") == {true, true}
  end

  # --- Extensions - PHP variants ---

  test "deflects .phtml requests" do
    assert deflected?("/shell.phtml") == {true, true}
  end

  test "deflects .php5 requests" do
    assert deflected?("/test.php5") == {true, true}
  end

  test "deflects .phar requests" do
    assert deflected?("/exploit.phar") == {true, true}
  end

  # --- Extensions - backup/config files ---

  test "deflects .bak requests" do
    assert deflected?("/config.bak") == {true, true}
  end

  test "deflects .sql requests" do
    assert deflected?("/dump.sql") == {true, true}
  end

  test "deflects .tar.gz requests" do
    assert deflected?("/backup.tar.gz") == {true, true}
  end

  test "deflects .zip requests" do
    assert deflected?("/site.zip") == {true, true}
  end

  test "deflects .log requests" do
    assert deflected?("/error.log") == {true, true}
  end

  test "deflects .yml requests" do
    assert deflected?("/docker-compose.yml") == {true, true}
  end

  test "deflects .swp requests" do
    assert deflected?("/config.swp") == {true, true}
  end

  # --- Paths - WordPress ---

  test "deflects wp-admin path" do
    assert deflected?("/wp-admin/install.php") == {true, true}
  end

  test "deflects xmlrpc path" do
    assert deflected?("/xmlrpc") == {true, true}
  end

  # --- Paths - PHP admin tools ---

  test "deflects phpmyadmin path" do
    assert deflected?("/phpmyadmin/index.php") == {true, true}
  end

  test "deflects phpinfo.php" do
    assert deflected?("/phpinfo.php") == {true, true}
  end

  test "deflects shell.php" do
    assert deflected?("/shell.php") == {true, true}
  end

  # --- Paths - Laravel ---

  test "deflects telescope path" do
    assert deflected?("/telescope") == {true, true}
  end

  test "deflects horizon path" do
    assert deflected?("/horizon/api") == {true, true}
  end

  # --- Paths - Node ---

  test "deflects node_modules path" do
    assert deflected?("/node_modules/express") == {true, true}
  end

  test "deflects package.json path" do
    assert deflected?("/package.json") == {true, true}
  end

  # --- Paths - Java/Tomcat/Spring ---

  test "deflects manager/html path" do
    assert deflected?("/manager/html") == {true, true}
  end

  test "deflects actuator subpath" do
    assert deflected?("/actuator/env") == {true, true}
  end

  # --- Paths - Jenkins ---

  test "deflects jenkins path" do
    assert deflected?("/jenkins/script") == {true, true}
  end

  # --- Paths - rich text editors ---

  test "deflects ckeditor path" do
    assert deflected?("/ckeditor/upload") == {true, true}
  end

  test "deflects fckeditor path" do
    assert deflected?("/fckeditor/editor") == {true, true}
  end

  # --- Paths - dotfiles ---

  test "deflects .git path" do
    assert deflected?("/.git/config") == {true, true}
  end

  test "deflects .aws path" do
    assert deflected?("/.aws/credentials") == {true, true}
  end

  test "deflects .docker path" do
    assert deflected?("/.docker/config.json") == {true, true}
  end

  test "deflects .ssh path" do
    assert deflected?("/.ssh/id_rsa") == {true, true}
  end

  # --- Paths - backups/dumps ---

  test "deflects dump path" do
    assert deflected?("/dump") == {true, true}
  end

  test "deflects backup.sql path" do
    assert deflected?("/backup.sql") == {true, true}
  end

  # --- Case insensitive ---

  test "deflects case-insensitive" do
    assert deflected?("/WP-ADMIN/setup.PHP") == {true, true}
  end

  # --- Logging ---

  test "logs deflected requests with method, path, and IP" do
    log =
      capture_log(fn ->
        conn(:get, "/wp-admin") |> PlugDeflect.call([])
      end)

    assert log =~ "Deflected"
    assert log =~ "GET"
    assert log =~ "/wp-admin"
    assert log =~ "127.0.0.1"
  end

  # --- Pass-through - legitimate requests must not be deflected ---

  test "passes through root" do
    conn = conn(:get, "/") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through app routes" do
    conn = conn(:get, "/users/settings") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through healthz" do
    conn = conn(:get, "/healthz") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through static assets" do
    conn = conn(:get, "/assets/app.js") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through CSS" do
    conn = conn(:get, "/assets/app.css") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through images" do
    conn = conn(:get, "/images/logo.png") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through API routes" do
    conn = conn(:get, "/api/v1/users") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through LiveView websocket" do
    conn = conn(:get, "/live/websocket") |> PlugDeflect.call([])
    refute conn.halted
  end

  # --- False positive guards ---

  test "passes through /status" do
    conn = conn(:get, "/status") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through /script" do
    conn = conn(:get, "/script") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through /debug" do
    conn = conn(:get, "/debug") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through /console" do
    conn = conn(:get, "/console") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through /admin/login" do
    conn = conn(:get, "/admin/login") |> PlugDeflect.call([])
    refute conn.halted
  end

  test "passes through /db" do
    conn = conn(:get, "/db") |> PlugDeflect.call([])
    refute conn.halted
  end
end
