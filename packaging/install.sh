#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "SentinelMilter must be installed as root." >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary="$script_dir/sentinelmilter"
config_source="$script_dir/configs/sentinelmilter.yaml"
prompt_source="$script_dir/configs/detection-prompt.txt"
service_source="$script_dir/packaging/systemd/sentinelmilter.service"

for required_file in "$binary" "$config_source" "$prompt_source"; do
    if [ ! -f "$required_file" ]; then
        echo "Required release file is missing: $required_file" >&2
        exit 1
    fi
done

if ! getent group sentinelmilter >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system sentinelmilter
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup -S sentinelmilter
    else
        echo "Cannot create the sentinelmilter group: groupadd/addgroup not found." >&2
        exit 1
    fi
fi

if ! id sentinelmilter >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --gid sentinelmilter --home-dir /nonexistent --shell /usr/sbin/nologin sentinelmilter
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -G sentinelmilter -s /sbin/nologin sentinelmilter
    else
        echo "Cannot create the sentinelmilter user: useradd/adduser not found." >&2
        exit 1
    fi
fi

install -m 0755 "$binary" /usr/local/sbin/sentinelmilter
install -d -o root -g sentinelmilter -m 0750 /etc/sentinelmilter
install -d -o sentinelmilter -g sentinelmilter -m 0750 /var/lib/sentinelmilter

install_config_if_missing() {
    source_file=$1
    destination_file=$2

    if [ -e "$destination_file" ]; then
        echo "Preserving existing $destination_file"
    else
        install -o root -g sentinelmilter -m 0640 "$source_file" "$destination_file"
        echo "Installed $destination_file"
    fi
}

install_config_if_missing "$config_source" /etc/sentinelmilter/sentinelmilter.yaml
install_config_if_missing "$prompt_source" /etc/sentinelmilter/detection-prompt.txt

if [ -f "$service_source" ] && command -v systemctl >/dev/null 2>&1; then
    install -m 0644 "$service_source" /etc/systemd/system/sentinelmilter.service
    systemctl daemon-reload
    echo "Installed the systemd service (not enabled or started)."
fi

echo "Installed SentinelMilter to /usr/local/sbin/sentinelmilter"
echo "Edit /etc/sentinelmilter/sentinelmilter.yaml, then validate it with:"
echo "  /usr/local/sbin/sentinelmilter --config /etc/sentinelmilter/sentinelmilter.yaml --check-config"
