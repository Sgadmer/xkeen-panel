#!/bin/sh
# Sgadmer/xkeen-panel. Run by the installation skill after a read-only audit.
set -eu
umask 077
ROOT=; BUNDLE=; REVIEWED=0; MIGRATION=0; CHECK=0; RESUME=; PORT=3000
fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
usage() {
    cat <<'EOF'
Проверенная установка XKeen Panel и первоначального стека XKeen/Xray.
  sh install.sh --check
  sh install.sh --bundle /opt/tmp/xkp-bundle --preflight-reviewed
  sh install.sh --bundle /opt/tmp/xkp-bundle --preflight-reviewed --migration-reviewed
  sh install.sh --resume /opt/etc/xkeen-panel-install.XXXXXX --preflight-reviewed --migration-reviewed

Комплект готовится на компьютере: python installer/prepare_bundle.py --help.
Версии и контрольные суммы фиксируются до копирования на роутер.
--preflight-reviewed означает, что агент проверил точную модель/прошивку,
Netfilter, память/накопитель, резервную копию KeeneticOS и план действий.
--migration-reviewed означает согласованный перенос прежней установки.
--port NUMBER задаёт LAN-порт новой панели (по умолчанию 3000).
Пароли, подписки и RCI-токены не передаются в аргументах этого установщика.
EOF
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) CHECK=1 ;;
        --bundle|--resume|--port|--test-root)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail "нет значения $1"
            case "$1" in --bundle) BUNDLE=$2;; --resume) RESUME=$2;; --port) PORT=$2;; --test-root) [ "${XKP_INSTALL_TESTING:-}" = 1 ] || fail 'test-root доступен только тестам'; ROOT=$2;; esac
            shift ;;
        --preflight-reviewed) REVIEWED=1 ;;
        --migration-reviewed) MIGRATION=1 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "неизвестный параметр $1" ;;
    esac
    shift
done
case "$ROOT" in ''|/*) ;; *) fail 'неверный корень теста';; esac
case "$PORT" in ''|*[!0-9]*) fail 'некорректный порт';; esac
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || fail 'порт должен быть от 1024 до 65535'
OPT=$ROOT/opt; DATA=$OPT/etc/xkeen-panel; BIN=$OPT/sbin/xkeen-panel; INIT=$OPT/etc/init.d/S99xkeen-panel
PATH=$OPT/sbin:$OPT/bin:$PATH
export PATH
arch() {
    ew=$(opkg print-architecture 2>/dev/null | awk '$2!="all" && $2!="noarch" {a=$2} END {print a}')
    case "$ew:$(uname -m)" in aarch64*:*|*:aarch64|*:arm64) echo aarch64;; mipsel*:*) echo mipsel;; *) return 1;; esac
}
if [ "$CHECK" = 1 ]; then
    printf 'architecture=%s\n' "$(arch || echo unsupported)"
    printf 'kernel=%s\n' "$(uname -r)"
    printf 'entware=%s\n' "$([ -d "$OPT/etc" ] && command -v opkg >/dev/null 2>&1 && echo found || echo missing)"
    printf 'ram_available_kib=%s\n' "$(awk '/^MemAvailable:/ {print $2}' "$ROOT/proc/meminfo" 2>/dev/null || true)"
    printf 'opt_free_kib=%s\n' "$(df -Pk "$OPT" 2>/dev/null | awk 'NR==2 {print $4}')"
    for name in xkeen xray xkeen-panel; do printf '%s=%s\n' "$name" "$([ -e "$OPT/sbin/$name" ] && echo found || echo absent)"; done
    for name in opkg ndmc jq curl tar sha256sum timeout; do command -v "$name" >/dev/null 2>&1 || printf 'missing_command=%s\n' "$name"; done
    say 'Это первичная диагностика. Полный аудит и проверка совместимости описаны в docs/installation.md.'
    exit 0
fi
[ "$REVIEWED" = 1 ] || fail 'сначала аудит и --preflight-reviewed'
[ "$(id -u)" = 0 ] || fail 'нужна оболочка Entware root, а не CLI KeeneticOS'
[ -d "$OPT/etc" ] && command -v opkg >/dev/null 2>&1 || fail 'нужно подготовить Entware через официальный веб-интерфейс'
[ -n "$ROOT" ] || command -v ndmc >/dev/null 2>&1 || fail 'поддерживаемая среда Keenetic/Netcraze не обнаружена'
for name in jq curl tar sha256sum timeout awk sed grep df du find; do command -v "$name" >/dev/null 2>&1 || fail "отсутствует $name; агент должен подготовить зависимости Entware"; done
ARCH=$(arch) || fail 'архитектура Entware не поддерживается'
[ ! -L "$BIN" ] && [ ! -L "$DATA" ] && [ ! -L "$INIT" ] || fail 'управляемый путь является символической ссылкой'
if [ -x "$OPT/sbin/xkeen" ] || [ -e "$BIN" ] || [ -d "$DATA/data" ]; then [ "$MIGRATION" = 1 ] || fail 'найдена предыдущая установка: сначала согласуйте миграцию'; fi
mkdir -p "$OPT/etc" "$OPT/tmp" "$OPT/var/lock"
LOCK=$OPT/var/lock/xkeen-panel-install.lock
mkdir "$LOCK" 2>/dev/null || fail 'установка заблокирована; проверьте PID и журнал предыдущего запуска'
printf '%s\n' "$$" > "$LOCK/pid"
STAGE=; MUTATED=0; COMPLETE=0; PANEL_RUNNING=0; CORE_RUNNING=0; PANEL_PAUSED=0
safe_stage() {
    base=$(basename "$1")
    printf '%s\n' "$base" | grep -Eq '^xkeen-panel-install\.[A-Za-z0-9]{6}$' || return 1
    [ "$1" = "$OPT/etc/$base" ] && [ -d "$1" ] && [ ! -L "$1" ] || return 1
    expected_parent=$(cd "$OPT/etc" && pwd -P) || return 1
    actual=$(cd "$1" && pwd -P) || return 1
    [ "$actual" = "$expected_parent/$base" ]
}
service() {
    if [ -n "$ROOT" ] && [ "${XKP_INSTALL_TESTING:-}" = 1 ]; then "$ROOT/.test-service" "$1" "$2"; else XKEEN_FOREGROUND=1 "$1" "$2"; fi
}
safe_target() {
    case "$1" in
        opt/sbin/xkeen|opt/sbin/.xkeen|opt/sbin/xray|opt/sbin/xkeen-panel|opt/etc/xkeen|opt/etc/xray|opt/etc/xkeen-panel|opt/etc/init.d/S05xkeen|opt/etc/init.d/S99xkeen-panel|opt/etc/ndm/netfilter.d/proxy.sh|opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh|opt/var/spool/cron/crontabs/root|opt/lib/opkg/status|opt/lib/opkg/info/xkeen.control|opt/lib/opkg/info/xkeen.list|opt/lib/opkg/info/xray.control|opt/lib/opkg/info/xray.list|opt/lib/opkg/info/xray.conffiles) return 0;; *) return 1;; esac
}
verify_backup() {
    [ -f "$STAGE/before.tar" ] && [ ! -L "$STAGE/before.tar" ] && [ -f "$STAGE/before.sha256" ] || return 1
    digest=$(cat "$STAGE/before.sha256")
    printf '%s\n' "$digest" | grep -Eq '^[a-f0-9]{64}$' || return 1
    [ "$(sha256sum "$STAGE/before.tar" | awk '{print $1}')" = "$digest" ] || return 1
    tar -tf "$STAGE/before.tar" > "$STAGE/backup-index.checked" || return 1
    tar -tvf "$STAGE/before.tar" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {bad=1} END {exit bad}' || return 1
    while IFS= read -r entry; do
        case "$entry" in /*|*'\\'*|*'..'*|*'//'*) return 1;; esac
        entry=${entry%/}; accepted=0
        while IFS= read -r managed; do
            safe_target "$managed" || return 1
            case "$entry" in "$managed"|"$managed"/*) accepted=1;; esac
        done < "$STAGE/managed"
        [ "$accepted" = 1 ] || return 1
    done < "$STAGE/backup-index.checked"
}
rollback() {
    safe_stage "$STAGE" || return 1
    # A failed/corrupt snapshot must never cause deletion of the live files.
    verify_backup || return 1
    [ ! -x "$INIT" ] || service "$INIT" stop >> "$STAGE/commands.log" 2>&1 || true
    if [ -x "$OPT/etc/init.d/S05xkeen" ] && [ "$(cat "$STAGE/mode")" = fresh ]; then service "$OPT/etc/init.d/S05xkeen" stop >> "$STAGE/commands.log" 2>&1 || true; fi
    while IFS= read -r relative; do
        safe_target "$relative" || return 1
        target=$ROOT/$relative
        [ ! -L "$target" ] || return 1
        # Only the explicit installation-owned allowlist is restored/deleted.
        if grep -Fx "$relative" "$STAGE/existed" >/dev/null; then
            parent=$(dirname "$target"); mkdir -p "$parent"
            [ ! -e "$target" ] || rm -rf "$target"
        else
            [ ! -e "$target" ] || rm -rf "$target"
        fi
    done < "$STAGE/managed"
    tar -xf "$STAGE/before.tar" -C "${ROOT:-/}" || return 1
    if [ "$(cat "$STAGE/mode")" = fresh ] && [ "$CORE_RUNNING" = 1 ]; then service "$OPT/etc/init.d/S05xkeen" start >> "$STAGE/commands.log" 2>&1 || return 1; fi
    [ "$PANEL_RUNNING" != 1 ] || service "$INIT" start >> "$STAGE/commands.log" 2>&1 || return 1
    printf 'rolled-back\n' > "$STAGE/status"
    say "Прежние управляемые файлы восстановлены: $STAGE"
}
cleanup() {
    status=$?; trap - EXIT HUP INT TERM
    if [ "$MUTATED" = 1 ] && [ "$COMPLETE" != 1 ]; then rollback || say "Откат не подтверждён; сохранён журнал $STAGE. Агент должен проверить состояние." >&2; fi
    if [ "$MUTATED" = 0 ] && [ "$PANEL_PAUSED" = 1 ] && [ "$PANEL_RUNNING" = 1 ]; then service "$INIT" start >> "$STAGE/commands.log" 2>&1 || say 'Не подтверждён повторный запуск прежней панели после ошибки snapshot.' >&2; fi
    if [ -f "$LOCK/pid" ] && [ "$(cat "$LOCK/pid")" = "$$" ]; then rm -f "$LOCK/pid"; rmdir "$LOCK"; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
if [ -n "$RESUME" ]; then
    safe_stage "$RESUME" || fail 'неверный каталог восстановления'
    STAGE=$RESUME
    [ "$(cat "$STAGE/status")" != complete ] || { say 'Эта установка уже завершена; сначала проверьте результат.'; COMPLETE=1; exit 0; }
    BUNDLE=$STAGE/bundle
    PANEL_RUNNING=$(cat "$STAGE/panel-running" 2>/dev/null || echo 0); CORE_RUNNING=$(cat "$STAGE/core-running" 2>/dev/null || echo 0)
    [ ! -f "$STAGE/before.tar" ] || { MUTATED=1; rollback || fail 'сначала требуется восстановить незавершённую транзакцию'; MUTATED=0; }
fi
[ -d "$BUNDLE" ] && [ ! -L "$BUNDLE" ] || fail 'нужен локальный проверенный комплект --bundle'
for name in bundle.json SHA256SUMS; do [ -f "$BUNDLE/$name" ] && [ ! -L "$BUNDLE/$name" ] || fail "нет $name"; done
EXPECTED=$(awk '$2=="bundle.json" {print $1}' "$BUNDLE/SHA256SUMS")
printf '%s\n' "$EXPECTED" | grep -Eq '^[a-f0-9]{64}$' || fail 'нет однозначной SHA256 bundle.json'
[ "$(sha256sum "$BUNDLE/bundle.json" | awk '{print $1}')" = "$EXPECTED" ] || fail 'manifest повреждён'
jq -e '.schema==1 and .repository=="Sgadmer/xkeen-panel" and (.mode=="fresh" or .mode=="panel") and (.files|type=="array" and length>0)' "$BUNDLE/bundle.json" >/dev/null || fail 'неизвестный формат комплекта'
[ "$(jq -r .architecture "$BUNDLE/bundle.json")" = "$ARCH" ] || fail 'комплект для другой архитектуры'
MODE=$(jq -r .mode "$BUNDLE/bundle.json")
VERSION=$(jq -r .panel_version "$BUNDLE/bundle.json")
printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' || fail 'неверная версия панели'
if [ "$MODE" = fresh ]; then
    [ "$(jq -r .adapter "$BUNDLE/bundle.json")" = xkeen-2.1-cores-none-v1 ] && [ "$(jq -r .xkeen_version "$BUNDLE/bundle.json")" = 2.1 ] || fail 'неизвестный адаптер чистой установки; проверена версия XKeen 2.1'
    [ ! -e "$OPT/sbin/xkeen" ] && [ ! -d "$OPT/etc/xray" ] && [ ! -e "$OPT/sbin/xray" ] || fail 'fresh предназначен для чистого прокси-стека; для миграции используйте panel-only или отдельно согласованный перенос'
else
    [ -x "$OPT/sbin/xkeen" ] && [ -x "$OPT/sbin/xray" ] || fail 'режим panel требует существующий рабочий XKeen/Xray'
fi
for pattern in '*xkeen-ui*' '*xkeen-go*' '*umarcheh*'; do
    for other in "$OPT/etc/init.d/"$pattern; do
        [ -f "$other" ] || continue
        grep -Eq '^ENABLED=(no|false|0)$' "$other" || fail "сначала согласуйте отключение конкурирующей службы $(basename "$other")"
    done
done
if [ -n "$(find "$BUNDLE" -type l -print)" ]; then fail 'символические ссылки в комплекте запрещены'; fi
ROWS=$(jq -r '.files[] | [.path,.sha256,(.bytes|tostring)] | @tsv' "$BUNDLE/bundle.json")
[ "$(printf '%s\n' "$ROWS" | cut -f1 | sort | uniq -d | wc -l | tr -d ' ')" = 0 ] || fail 'повторяющиеся пути manifest'
TOTAL=0
TAB=$(printf '\t')
while IFS="$TAB" read -r file digest bytes; do
    printf '%s\n' "$file" | grep -Eq '^(panel|core/(xray|xkeen|\.xkeen/[A-Za-z0-9_./-]+)|geodata/(geosite_v2fly|geoip_v2fly)\.dat)$' || fail 'неразрешённый путь в комплекте'
    case "/$file/" in */../*|*/./*) fail 'небезопасный путь';; esac
    printf '%s\n' "$digest:$bytes" | grep -Eq '^[a-f0-9]{64}:[0-9]+$' || fail 'неверные метаданные файла'
    [ -f "$BUNDLE/$file" ] && [ ! -L "$BUNDLE/$file" ] || fail "отсутствует $file"
    [ "$(wc -c < "$BUNDLE/$file" | tr -d ' ')" = "$bytes" ] || fail 'размер файла отличается'
    [ "$(sha256sum "$BUNDLE/$file" | awk '{print $1}')" = "$digest" ] || fail 'контрольная сумма файла отличается'
    TOTAL=$((TOTAL + bytes))
done <<EOF
$ROWS
EOF
actual_files=$(find "$BUNDLE" -type f | wc -l | tr -d ' ')
listed_files=$(printf '%s\n' "$ROWS" | wc -l | tr -d ' ')
[ "$actual_files" = "$((listed_files + 2))" ] || fail 'в комплекте есть файлы вне manifest'
[ -f "$BUNDLE/panel" ] || fail 'в комплекте нет панели'
if [ "$MODE" = fresh ]; then
    for file in core/xray core/xkeen core/.xkeen/import.sh geodata/geoip_v2fly.dat geodata/geosite_v2fly.dat; do grep -F "$(printf '%s\t' "$file")" <<EOF >/dev/null || fail "в manifest нет $file"
$ROWS
EOF
    done
fi
RAM=$(awk '/^MemAvailable:/ {print $2}' "$ROOT/proc/meminfo")
MIN_RAM=$(jq -r .min_available_ram_kib "$BUNDLE/bundle.json"); RESERVE=$(jq -r .reserve_kib "$BUNDLE/bundle.json")
printf '%s\n' "$MIN_RAM:$RESERVE" | grep -Eq '^[0-9]+:[0-9]+$' || fail 'нет бюджета ресурсов'
[ -n "$RAM" ] && [ "$RAM" -ge "$MIN_RAM" ] || fail 'свободная RAM ниже бюджета выбранного комплекта'
FREE=$(df -Pk "$OPT" | awk 'NR==2 {print $4}')
BACKUP=$(du -sk "$DATA" "$OPT/etc/xray" "$OPT/etc/xkeen" "$OPT/sbin/.xkeen" "$OPT/sbin/xray" "$OPT/sbin/xkeen" "$BIN" 2>/dev/null | awk '{n+=$1} END {print n+0}')
NEED=$(( (TOTAL * 2 + 1023) / 1024 + BACKUP + RESERVE ))
[ "$FREE" -ge "$NEED" ] || fail "недостаточно места на /opt: требуется $NEED КиБ с учётом stage/backup/резерва"
STAGE=$(mktemp -d "$OPT/etc/xkeen-panel-install.XXXXXX"); chmod 700 "$STAGE"
cp -R "$BUNDLE" "$STAGE/bundle"; BUNDLE=$STAGE/bundle
printf '%s\n' "$MODE" > "$STAGE/mode"; printf 'verified\n' > "$STAGE/status"
cat > "$STAGE/managed" <<'EOF'
opt/sbin/xkeen-panel
opt/etc/xkeen-panel
opt/etc/init.d/S99xkeen-panel
EOF
if [ "$MODE" = fresh ]; then cat >> "$STAGE/managed" <<'EOF'
opt/sbin/xkeen
opt/sbin/.xkeen
opt/sbin/xray
opt/etc/xkeen
opt/etc/xray
opt/etc/init.d/S05xkeen
opt/etc/ndm/netfilter.d/proxy.sh
opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh
opt/var/spool/cron/crontabs/root
opt/lib/opkg/status
opt/lib/opkg/info/xkeen.control
opt/lib/opkg/info/xkeen.list
opt/lib/opkg/info/xray.control
opt/lib/opkg/info/xray.list
opt/lib/opkg/info/xray.conffiles
EOF
fi
: > "$STAGE/existed"
while IFS= read -r relative; do
    safe_target "$relative" || fail 'неверный путь резервного копирования'
    [ ! -L "$ROOT/$relative" ] || fail 'ссылка в управляемых путях'
    if [ -e "$ROOT/$relative" ]; then
        [ -z "$(find "$ROOT/$relative" -type l -print)" ] || fail 'ссылка внутри управляемых путей'
        printf '%s\n' "$relative" >> "$STAGE/existed"
    fi
done < "$STAGE/managed"
[ -z "$(pidof xkeen-panel 2>/dev/null || true)" ] || PANEL_RUNNING=1
[ -z "$(pidof xray 2>/dev/null || true)" ] || CORE_RUNNING=1
printf '%s\n' "$PANEL_RUNNING" > "$STAGE/panel-running"; printf '%s\n' "$CORE_RUNNING" > "$STAGE/core-running"
if [ "$PANEL_RUNNING" = 1 ]; then
    [ -x "$INIT" ] || fail 'панель запущена без известной службы; сначала согласуйте способ её остановки'
    PANEL_PAUSED=1
    service "$INIT" stop >> "$STAGE/commands.log" 2>&1 || fail 'не удалось приостановить прежнюю панель для согласованного snapshot'
    attempts=0
    while [ -n "$(pidof xkeen-panel 2>/dev/null || true)" ] && [ "$attempts" -lt 5 ]; do attempts=$((attempts+1)); sleep 1; done
    [ -z "$(pidof xkeen-panel 2>/dev/null || true)" ] || fail 'прежняя панель ещё работает; snapshot не создаётся'
fi
tar -cf "$STAGE/before.tar" -C "${ROOT:-/}" -T "$STAGE/existed"
sha256sum "$STAGE/before.tar" | awk '{print $1}' > "$STAGE/before.sha256"
verify_backup || fail 'не удалось проверить резервную копию до применения'
printf 'backed-up\n' > "$STAGE/status"
MUTATED=1
[ ! -x "$INIT" ] || service "$INIT" stop >> "$STAGE/commands.log" 2>&1
mkdir -p "$OPT/sbin" "$OPT/etc/init.d" "$OPT/var/log"
if [ "$MODE" = fresh ]; then
    [ -z "$ROOT" ] || [ "${XKP_INSTALL_TESTING:-}" = 1 ] || fail 'неверный тестовый корень'
    cp "$BUNDLE/core/xray" "$OPT/sbin/xray"; chmod 755 "$OPT/sbin/xray"
    cp "$BUNDLE/core/xkeen" "$OPT/sbin/xkeen"; chmod 755 "$OPT/sbin/xkeen"
    cp -R "$BUNDLE/core/.xkeen" "$OPT/sbin/.xkeen"
    find "$OPT/sbin/.xkeen" -type d -exec chmod 700 '{}' ';'
    find "$OPT/sbin/.xkeen" -type f -exec chmod 700 '{}' ';'
    timeout 20 "$OPT/sbin/xray" version > "$STAGE/core-version.log" 2>&1 || fail 'выбранный Xray не запускается'
    want_xray=$(jq -r .xray_version "$BUNDLE/bundle.json" | sed 's/^v//')
    grep -F "$want_xray" "$STAGE/core-version.log" >/dev/null || fail 'версия Xray отличается от выбранной'
    printf 'configuring-xkeen\n' > "$STAGE/status"
    # No unpinned core/geodata downloads: an exact verified core already exists.
    LC_ALL=C XKEEN_FOREGROUND=1 timeout 600 "$OPT/sbin/xkeen" -i auto cores=none geo=off geoipset=off cron=off autostart=off >> "$STAGE/commands.log" 2>&1 || fail 'подготовка выбранного XKeen не завершена'
    [ -x "$OPT/etc/init.d/S05xkeen" ] || fail 'не создана служба XKeen'
    timeout 20 "$OPT/sbin/xkeen" -v > "$STAGE/xkeen-version.log" 2>&1 || fail 'не удалось проверить версию XKeen'
    want_xkeen=$(jq -r .xkeen_version "$BUNDLE/bundle.json" | sed 's/^v//')
    grep -F "$want_xkeen" "$STAGE/xkeen-version.log" >/dev/null || fail 'версия XKeen отличается от выбранной'
    mkdir -p "$OPT/etc/xray/dat"
    cp "$BUNDLE/geodata/geoip_v2fly.dat" "$BUNDLE/geodata/geosite_v2fly.dat" "$OPT/etc/xray/dat/"
    service "$OPT/etc/init.d/S05xkeen" stop >> "$STAGE/commands.log" 2>&1 || true
    [ -z "$(pidof xray 2>/dev/null || true)" ] || fail 'ядро должно оставаться остановленным до проверки подписки'
fi
chmod 700 "$BUNDLE/panel"
timeout 10 "$BUNDLE/panel" -version > "$STAGE/panel-version.log" 2>&1 || fail 'панель не запускается на этой архитектуре'
grep -F "$VERSION" "$STAGE/panel-version.log" >/dev/null || fail 'версия панели отличается'
cp "$BUNDLE/panel" "$BIN.install-next"; chmod 755 "$BIN.install-next"; mv "$BIN.install-next" "$BIN"
mkdir -p "$DATA/data"; chmod 700 "$DATA" "$DATA/data"
if [ ! -f "$DATA/config.yaml" ]; then cat > "$DATA/config.yaml" <<EOF
port: $PORT
data_dir: /opt/etc/xkeen-panel/data
xkeen_path: /opt/sbin/xkeen
outbounds_file: /opt/etc/xray/configs/04_outbounds.json
log_file: /opt/var/log/xkeen-panel.log
subscription_refresh_interval: 3600
check_interval: 120
check_url: https://www.google.com/generate_204
max_fails: 3
EOF
    chmod 600 "$DATA/config.yaml"
else
    existing_port=$(awk '$1=="port:" {print $2; exit}' "$DATA/config.yaml")
    [ "$existing_port" = "$PORT" ] || fail 'порт существующей панели отличается; укажите его явно'
fi
cat > "$INIT" <<'EOF'
#!/bin/sh
ENABLED=yes
PROCS="xkeen-panel"
ARGS="-config /opt/etc/xkeen-panel/config.yaml"
DESC="XKeen Panel"
PREARGS=""
. /opt/etc/init.d/rc.func
EOF
chmod 755 "$INIT"
printf 'starting-panel\n' > "$STAGE/status"
service "$INIT" start >> "$STAGE/commands.log" 2>&1 || fail 'не удалось запустить службу панели'
ready=0; n=0
while [ "$n" -lt 30 ]; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/api/auth/status" > "$STAGE/auth-status.json" 2>/dev/null && grep -Eq '"setup_required"[[:space:]]*:' "$STAGE/auth-status.json"; then ready=1; break; fi
    n=$((n+1)); sleep 1
done
[ "$ready" = 1 ] || fail 'панель не ответила корректно; выполняется откат'
printf 'complete\n' > "$STAGE/status"; COMPLETE=1
say "Панель $VERSION установлена. Журнал и резервная копия: $STAGE"
say "Адрес: http://<LAN-адрес-роутера>:$PORT. Агент должен определить точный адрес, защитить вход, импортировать источник, выбрать режим VPN и проверить реальный трафик."
say 'Установленные файлы ещё не означают работающий VPN: завершите мастер и HTTPS/исключения/перезапуск по скиллу.'
