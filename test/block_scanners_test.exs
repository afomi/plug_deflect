defmodule BlockScannersTest do
  use ExUnit.Case, async: true
  import Plug.Test

  # Extensions - original
  test "blocks .php requests" do
    conn = conn(:get, "/wp-login.php") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .asp requests" do
    conn = conn(:get, "/admin.asp") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .env requests" do
    conn = conn(:get, "/.env") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Extensions - new
  test "blocks .bak requests" do
    conn = conn(:get, "/config.bak") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .sql requests" do
    conn = conn(:get, "/dump.sql") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .tar.gz requests" do
    conn = conn(:get, "/backup.tar.gz") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .zip requests" do
    conn = conn(:get, "/site.zip") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .log requests" do
    conn = conn(:get, "/error.log") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .yml requests" do
    conn = conn(:get, "/docker-compose.yml") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .swp requests" do
    conn = conn(:get, "/config.swp") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - WordPress
  test "blocks wp-admin path" do
    conn = conn(:get, "/wp-admin/install.php") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks xmlrpc path" do
    conn = conn(:get, "/xmlrpc") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks phpmyadmin path" do
    conn = conn(:get, "/phpmyadmin/index.php") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - Laravel
  test "blocks telescope path" do
    conn = conn(:get, "/telescope") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks horizon path" do
    conn = conn(:get, "/horizon/api") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - Node
  test "blocks node_modules path" do
    conn = conn(:get, "/node_modules/express") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks package.json path" do
    conn = conn(:get, "/package.json") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - Java/Tomcat/Spring
  test "blocks manager path" do
    conn = conn(:get, "/manager/html") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks actuator subpath" do
    conn = conn(:get, "/actuator/env") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - Jenkins
  test "blocks jenkins path" do
    conn = conn(:get, "/jenkins/script") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - dotfiles
  test "blocks .git path" do
    conn = conn(:get, "/.git/config") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .aws path" do
    conn = conn(:get, "/.aws/credentials") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks .docker path" do
    conn = conn(:get, "/.docker/config.json") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Paths - backups/dumps
  test "blocks dump path" do
    conn = conn(:get, "/dump") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  test "blocks backup.sql path" do
    conn = conn(:get, "/backup.sql") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Case insensitive
  test "blocks case-insensitive" do
    conn = conn(:get, "/WP-ADMIN/setup.PHP") |> BlockScanners.call([])
    assert conn.status == 404
    assert conn.halted
  end

  # Pass-through - legitimate requests must not be blocked
  test "passes through normal requests" do
    conn = conn(:get, "/") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through app routes" do
    conn = conn(:get, "/users/settings") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through healthz" do
    conn = conn(:get, "/healthz") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through static assets" do
    conn = conn(:get, "/assets/app.js") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through CSS" do
    conn = conn(:get, "/assets/app.css") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through images" do
    conn = conn(:get, "/images/logo.png") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through API routes" do
    conn = conn(:get, "/api/v1/users") |> BlockScanners.call([])
    refute conn.halted
  end

  test "passes through LiveView websocket" do
    conn = conn(:get, "/live/websocket") |> BlockScanners.call([])
    refute conn.halted
  end
end
