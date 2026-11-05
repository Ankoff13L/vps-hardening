#!/bin/bash
#
# hardening.sh — Interactive VPS hardening for Ubuntu 24.04
#
# Возможности:
#   - Создание изолированного sudo-пользователя
#   - Модульный харденинг SSH (drop-in 00-hardening.conf, приоритет над cloud-init)
#   - Обязательная проверка sshd -t перед рестартом (защита от локаута)
#   - UFW с блокировкой почтовых спам-портов
#   - Fail2ban
#   - Опциональная 2FA через keyboard-interactive (пароль + OTP)
#   - unattended-upgrades, Logwatch, авто-очистка диска
#
# Запуск: sudo ./hardening.sh
#

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# ─── Цвета ────────────────────────────────────────────────────────────────────
GREEN="\033[32m"
BOLD="\033[1m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

# ─── Проверка прав ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] Ошибка: запустите с правами root (sudo ./hardening.sh).${RESET}"
    exit 1
fi

echo "=========================================================="
echo " ИНТЕРАКТИВНАЯ НАСТРОЙКА БЕЗОПАСНОСТИ VPS"
echo " (UBUNTU 24.04 | PASSWORD + OPTIONAL GOOGLE AUTHENTICATOR)"
echo "=========================================================="
echo ""

# ─── 1. Интерактивный опрос ───────────────────────────────────────────────────
read -p "Введите имя нового sudo-пользователя [deploy]: " NEW_USER
NEW_USER=${NEW_USER:-deploy}

if [ "$NEW_USER" = "root" ]; then
    echo -e "${RED}[-] Ошибка: имя 'root' запрещено.${RESET}"
    exit 1
fi

while true; do
    read -s -p "Введите пароль для $NEW_USER: " NEW_USER_PASSWORD; echo
    read -s -p "Повторите пароль: " NEW_USER_PASSWORD_CONFIRM; echo
    if [ "$NEW_USER_PASSWORD" = "$NEW_USER_PASSWORD_CONFIRM" ] && [ -n "$NEW_USER_PASSWORD" ]; then
        break
    fi
    echo -e "${RED}[-] Пароли не совпадают или пусты.${RESET}"
done

read -p "Введите новый порт для SSH [43780]: " CUSTOM_SSH_PORT
CUSTOM_SSH_PORT=${CUSTOM_SSH_PORT:-43780}

AUTO_IP=$(curl -4 -s --connect-timeout 2 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
read -p "Введите внешний IP сервера [${AUTO_IP:-не определен}]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$AUTO_IP}

read -p "Дополнительные порты через пробел (например '80 443', пусто = нет): " EXTRA_PORTS

ask_yes_no() {
    local prompt="$1" default="${2:-y}" answer
    read -p "$prompt [y/n]: " answer
    answer=${answer:-$default}
    [[ "$answer" =~ ^[Yy]$ ]]
}

if ask_yes_no "Устанавливать Fail2ban?"; then SETUP_FAIL2BAN=true; else SETUP_FAIL2BAN=false; fi
if ask_yes_no "Настраивать Google Authenticator 2FA?"; then SETUP_2FA=true; else SETUP_2FA=false; fi
if ask_yes_no "Включить unattended-upgrades?"; then SETUP_UNATTENDED=true; else SETUP_UNATTENDED=false; fi
if ask_yes_no "Настроить ежедневный Logwatch?"; then SETUP_LOGWATCH=true; else SETUP_LOGWATCH=false; fi
if ask_yes_no "Авто-очистка диска при <15% свободного?"; then SETUP_CLEANUP=true; else SETUP_CLEANUP=false; fi

echo ""
echo "=== [1/7] Обновление системы и базовые утилиты ==="
apt-get update
apt-get -y upgrade
apt-get -y autoremove || true
apt-get install -y ufw curl git htop sudo cron

if [ "$SETUP_2FA" = true ]; then
    apt-get install -y libpam-google-authenticator
fi

echo "=== [2/7] Пользователь $NEW_USER ==="
if id "$NEW_USER" &>/dev/null; then
    echo "[!] Пользователь $NEW_USER уже существует — обновляем пароль."
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
else
    adduser --gecos "" "$NEW_USER"
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
    usermod -aG sudo "$NEW_USER"
fi

echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$NEW_USER"
chmod 0440 "/etc/sudoers.d/$NEW_USER"
if ! visudo -cf "/etc/sudoers.d/$NEW_USER" >/dev/null; then
    echo -e "${RED}[-] Ошибка синтаксиса sudoers!${RESET}"
    rm -f "/etc/sudoers.d/$NEW_USER"
    exit 1
fi
echo -e "${GREEN}[+] Пользователь $NEW_USER настроен.${RESET}"

echo "=== [3/7] SSH hardening (drop-in + socket) ==="
mkdir -p /etc/ssh/sshd_config.d

# Гарантируем наличие Include в основном sshd_config
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi

SSH_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
[ -f "$SSH_DROPIN" ] && cp "$SSH_DROPIN" "${SSH_DROPIN}.bak.$(date +%s)"

{
    echo "# Managed by hardening.sh on $(date -u +%FT%TZ)"
    echo "Port $CUSTOM_SSH_PORT"
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication no"
    echo "UsePAM yes"
    if [ "$SETUP_2FA" = true ]; then
        # Обязательный многошаговый диалог: пароль (pam_unix) + OTP (google-authenticator)
        echo "PasswordAuthentication no"
        echo "KbdInteractiveAuthentication yes"
        echo "AuthenticationMethods keyboard-interactive"
    else
        # Обычный вход по паролю
        echo "PasswordAuthentication yes"
        echo "KbdInteractiveAuthentication no"
    fi
} > "$SSH_DROPIN"
chmod 0600 "$SSH_DROPIN"

# Настройка ssh.socket (Ubuntu 24.04 socket activation)
if systemctl cat ssh.socket &>/dev/null; then
    echo "[*] Обнаружен ssh.socket — настраиваем systemd override для порта $CUSTOM_SSH_PORT."
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat > /etc/systemd/system/ssh.socket.d/override.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$CUSTOM_SSH_PORT
ListenStream=[::]:$CUSTOM_SSH_PORT
EOF
    systemctl daemon-reload
fi

echo "=== [4/7] UFW ==="
ufw default deny incoming
ufw default allow outgoing
ufw deny 25/tcp
ufw deny 465/tcp
ufw deny 587/tcp
ufw deny 2525/tcp
ufw allow "$CUSTOM_SSH_PORT/tcp"
for port in $EXTRA_PORTS; do
    echo "[+] Открываем порт: $port"
    ufw allow "$port"
done
ufw --force enable
echo -e "${GREEN}[+] UFW активирован. SSH порт: $CUSTOM_SSH_PORT.${RESET}"

echo "=== [5/7] Fail2ban ==="
if [ "$SETUP_FAIL2BAN" = true ]; then
    apt-get install -y fail2ban
    cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
backend = systemd
port = $CUSTOM_SSH_PORT
maxretry = 3
bantime = 1h
findtime = 10m
EOF
    systemctl enable --now fail2ban
    systemctl restart fail2ban
    echo -e "${GREEN}[+] Fail2ban настроен.${RESET}"
else
    echo "[*] Fail2ban пропущен."
fi

echo "=== [6/7] Аутентификация SSH (PAM) ==="
PAM_FILE="/etc/pam.d/sshd"
[ ! -f "${PAM_FILE}.hardening-backup" ] && cp "$PAM_FILE" "${PAM_FILE}.hardening-backup"

# Удаляем возможные дубликаты от предыдущих запусков
sed -i '/pam_google_authenticator\.so/d' "$PAM_FILE"

if [ "$SETUP_2FA" = true ]; then
    # Пароль (common-auth) → OTP (google-authenticator): оба обязательны
    sed -i '/^@include common-auth$/a auth required pam_google_authenticator.so' "$PAM_FILE"
    echo "[*] PAM настроен: пароль + OTP (без nullok)."
else
    echo "[*] 2FA отключён — вход только по паролю."
fi

echo "[*] Проверка синтаксиса sshd..."
mkdir -p /run/sshd && chmod 0755 /run/sshd
if ! sshd -t; then
    echo -e "${RED}[-] ОШИБКА: sshd -t провалился. Рестарт отменён.${RESET}"
    echo "    Восстановите ${PAM_FILE} из ${PAM_FILE}.hardening-backup при необходимости."
    exit 1
fi
echo -e "${GREEN}[+] sshd -t OK.${RESET}"

# Генерация 2FA ДО рестарта — чтобы новая конфигурация уже видела ~/.google_authenticator
if [ "$SETUP_2FA" = true ]; then
    echo ""
    echo "=========================================================="
    echo " ГЕНЕРАЦИЯ 2FA для пользователя $NEW_USER"
    echo " Отсканируйте QR-код в Google Authenticator / FreeOTP."
    echo " Сохраните аварийные коды!"
    echo "=========================================================="
    read -p "Нажмите Enter для генерации..."
    su - "$NEW_USER" -c 'google-authenticator -t -d -f -r 3 -R 30'

    GA_FILE="/home/$NEW_USER/.google_authenticator"
    if [ ! -f "$GA_FILE" ]; then
        echo -e "${RED}[-] ОШИБКА: $GA_FILE не создан. 2FA не сработает.${RESET}"
        echo "    Текущая SSH-сессия сохранена. Исправьте вручную и перезапустите скрипт."
        exit 1
    fi
    chmod 0600 "$GA_FILE"
    chown "$NEW_USER:$NEW_USER" "$GA_FILE"
    echo -e "${GREEN}[+] Файл 2FA: $GA_FILE (права 0600).${RESET}"
fi

# Финальный рестарт SSH
echo "[*] Рестарт SSH-служб..."
systemctl daemon-reload
if systemctl cat ssh.socket &>/dev/null; then
    systemctl restart ssh.socket
fi
if systemctl cat ssh.service &>/dev/null; then
    systemctl restart ssh.service
else
    systemctl restart ssh
fi
echo -e "${GREEN}[+] SSH перезапущен.${RESET}"

# Показ применённых параметров — визуальная проверка победы над cloud-init
echo ""
echo "=== Применённая конфигурация SSH (sshd -T) ==="
sshd -T 2>/dev/null | grep -E '^(port|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|usepam|permitrootlogin|pubkeyauthentication) ' || true

echo "=== [7/7] Фоновое обслуживание ==="

# Unattended-upgrades
if [ "$SETUP_UNATTENDED" = true ]; then
    apt-get install -y unattended-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    grep -q 'Remove-Unused-Dependencies' /etc/apt/apt.conf.d/50unattended-upgrades \
        || echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e "${GREEN}[+] Автообновления включены.${RESET}"
fi

# Logwatch
if [ "$SETUP_LOGWATCH" = true ]; then
    apt-get install -y logwatch
    mkdir -p /var/log/logwatch_reports
    cat > /etc/cron.daily/custom-logwatch <<'EOF'
#!/bin/bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
REPORT_DIR="/var/log/logwatch_reports"
mkdir -p "$REPORT_DIR"
rm -rf /tmp/logwatch.*
logwatch --output file --filename "$REPORT_DIR/report_$(date +%Y-%m-%d).txt" --range yesterday --detail med
find "$REPORT_DIR" -type f -mtime +30 -delete
EOF
    chmod +x /etc/cron.daily/custom-logwatch
    echo -e "${GREEN}[+] Logwatch настроен (хранение 30 дней).${RESET}"
fi

# Disk cleanup
if [ "$SETUP_CLEANUP" = true ]; then
    cat > /usr/local/bin/vps-disk-cleanup.sh <<'EOF'
#!/bin/bash
FREE_PERCENT=$(df / --output=pcent | tail -1 | tr -d ' %')
if [ "$FREE_PERCENT" -gt 85 ]; then
    apt-get clean
    journalctl --vacuum-time=7d
    rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
fi
EOF
    chmod +x /usr/local/bin/vps-disk-cleanup.sh
    echo "0 3 * * * root /usr/local/bin/vps-disk-cleanup.sh" > /etc/cron.d/vps-disk-cleanup
    chmod 0644 /etc/cron.d/vps-disk-cleanup
    echo -e "${GREEN}[+] Авто-очистка диска настроена.${RESET}"
fi

# ─── Итог ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}==========================================================${RESET}"
echo -e "${GREEN}${BOLD} СЕРВЕР УСПЕШНО НАСТРОЕН!${RESET}"
echo -e " Пользователь:       ${CYAN}$NEW_USER${RESET}"
echo -e " SSH порт:           ${CYAN}$CUSTOM_SSH_PORT${RESET}"
echo -e " IP-адрес:           ${CYAN}$SERVER_IP${RESET}"
echo -e " 2FA:                ${CYAN}$([ "$SETUP_2FA" = true ] && echo 'Включена (пароль + OTP)' || echo 'Выключена')${RESET}"
echo ""
echo -e " Проверьте вход (НЕ закрывая текущую сессию):"
echo -e " ${BOLD}ssh -p $CUSTOM_SSH_PORT $NEW_USER@$SERVER_IP${RESET}"
if [ "$SETUP_2FA" = true ]; then
    echo -e " (затем введите пароль и 6-значный код из приложения)"
else
    echo -e " (только пароль)"
fi
echo -e "${YELLOW}==========================================================${RESET}"
