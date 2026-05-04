#!/usr/bin/env bash
#
# leaks.sh — check for common source / config leaks on a webroot.
#
# Used in playbook 12 §12.8.
#
# Usage:
#   ./leaks.sh https://target.example
#
# Output: status code per path. 200 / 206 / 301-302 (to file) are
# candidates for leak. 403 / 404 are normal.
#
set -euo pipefail

if [ -z "${1-}" ]; then
  echo "usage: $0 https://target.example" >&2
  exit 1
fi

BASE="${1%/}"
UA="OBSIDIAN/1.0 (+playbook-12-leaks)"

PATHS=(
  # Source control
  "/.git/HEAD"
  "/.git/config"
  "/.git/index"
  "/.git/logs/HEAD"
  "/.gitignore"
  "/.gitattributes"
  "/.svn/entries"
  "/.svn/wc.db"
  "/.hg/store/00manifest.i"
  "/.bzr/checkout/dirstate"
  # Editor / IDE backups
  "/.DS_Store"
  "/.idea/workspace.xml"
  "/.idea/.gitignore"
  "/.vscode/settings.json"
  "/.vscode/launch.json"
  # Env / config
  "/.env"
  "/.env.local"
  "/.env.production"
  "/.env.dev"
  "/.env.staging"
  "/.env.test"
  "/.env.bak"
  "/.env.old"
  "/.env.save"
  "/.env~"
  "/config.php"
  "/config.php.bak"
  "/config.php.old"
  "/config.php.swp"
  "/config.json"
  "/config.yml"
  "/config.yaml"
  "/wp-config.php.bak"
  "/wp-config.php.old"
  "/wp-config.php.save"
  "/wp-config.php.swp"
  # Build / deploy
  "/Dockerfile"
  "/docker-compose.yml"
  "/docker-compose.yaml"
  "/docker-compose.override.yml"
  "/.dockerignore"
  "/Makefile"
  "/Procfile"
  "/composer.json"
  "/composer.lock"
  "/package.json"
  "/package-lock.json"
  "/yarn.lock"
  "/Pipfile"
  "/Pipfile.lock"
  "/requirements.txt"
  "/Gemfile"
  "/Gemfile.lock"
  "/go.mod"
  "/go.sum"
  "/Cargo.toml"
  "/Cargo.lock"
  # CI / build artifacts
  "/.travis.yml"
  "/.circleci/config.yml"
  "/.gitlab-ci.yml"
  "/.github/workflows/ci.yml"
  "/Jenkinsfile"
  "/azure-pipelines.yml"
  "/buildspec.yml"
  # Backups
  "/backup.sql"
  "/backup.zip"
  "/backup.tar"
  "/backup.tar.gz"
  "/backup.tgz"
  "/db.sql"
  "/dump.sql"
  "/database.sql"
  "/site.zip"
  "/site.tar.gz"
  "/www.zip"
  "/www.tar.gz"
  "/htdocs.zip"
  # Server status / debug
  "/server-status"
  "/server-info"
  "/phpinfo.php"
  "/info.php"
  "/test.php"
  "/debug.php"
  "/.well-known/security.txt"
  "/.well-known/openid-configuration"
  # Web frameworks
  "/_profiler/"
  "/_wdt/"
  "/_ignition/health-check"
  "/telescope/"
  "/horizon/"
  "/actuator/"
  "/actuator/env"
  "/actuator/health"
  "/actuator/heapdump"
  "/actuator/jolokia"
  "/elmah.axd"
  "/trace.axd"
  "/api-docs"
  "/swagger.json"
  "/swagger-ui/"
  "/swagger/index.html"
  "/openapi.json"
  "/graphql"
  "/graphiql"
  # Logs
  "/storage/logs/laravel.log"
  "/storage/logs/laravel-2024.log"
  "/storage/logs/laravel-2025.log"
  "/storage/logs/laravel-2026.log"
  "/log/development.log"
  "/log/production.log"
  "/error.log"
  "/access.log"
  # Misc leaks
  "/sitemap.xml"
  "/robots.txt"
  "/crossdomain.xml"
  "/clientaccesspolicy.xml"
  "/humans.txt"
  "/security.txt"
)

printf "%-6s %-10s %s\n" "STATUS" "LENGTH" "PATH"
printf "%-6s %-10s %s\n" "------" "------" "----"

for path in "${PATHS[@]}"; do
  url="$BASE$path"
  out=$(curl -sk -o /dev/null \
        -H "User-Agent: $UA" \
        -w "%{http_code} %{size_download}" \
        --max-time 10 \
        "$url" || echo "ERR 0")
  code="${out%% *}"
  size="${out##* }"
  case "$code" in
    200|206|301|302)
      printf "\033[31m%-6s %-10s %s\033[0m\n" "$code" "$size" "$path"
      ;;
    401|403)
      printf "%-6s %-10s %s\n" "$code" "$size" "$path"
      ;;
    *) ;;
  esac
done

echo
echo "Lines highlighted in red are candidates for source / config leaks."
echo "Inspect each manually before opening a finding (some 200s are intended)."
