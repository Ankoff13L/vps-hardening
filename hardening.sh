#!/bin/bash
#
# hardening.sh — Interactive VPS hardening for Ubuntu 24.04
#
# Что делает:
#   1. Обновляет систему и ставит базовые утилиты
#   2. Создаёт изолированного sudo-пользователя (sudoers 0440, проверка visudo)
#   3. Харденит SSH через drop-in 00-hardening.conf (приоритет над cloud-init)
#   4. Настраивает UFW + блокировка спам-портов
#   5. Опционально Fail2ban
#   6. Опционально 2FA (пароль + Google Authenticator через keyboard-interactive)
#   7. Опционально unattended-upgrades, Logwatch, авто-очистка диска
#
# ВАЖНО:
#   - Запускать из настоящего терминала (не `ssh host 'bash script.sh'`),
#     иначе QR-код 2FA может не отобразиться.
#   - НЕ закрывать текущую SSH-сессию, пока не проверите вход в новом окне.
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

# ─── 2. Пользователь ──────────────────────────────────────────────────────────
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

# ─── 3. SSH drop-in + socket ──────────────────────────────────────────────────
echo "=== [3/7] SSH hardening (drop-in + socket) ==="
mkdir -p /etc/ssh/sshd_config.d

# Гарантируем наличие Include в основном sshd_config (на Ubuntu 24.04 он уже есть,
# но проверим на всякий случай)
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi

# Имя 00-hardening.conf специально с префиксом 00-, чтобы сортироваться РАНЬШЕ
# cloud-init (50-cloud-init.conf, 60-cloud-init.conf). В OpenSSH побеждает
# первое встреченное значение директивы (first-match-wins).
SSH_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
[ -f "$SSH_DROPIN" ] && cp "$SSH_DROPIN" "${SSH_DROPIN}.bak.$(date +%s)"

{
    echo "# Managed by hardening.sh on $(date -u +%FT%TZ)"
    echo "Port $CUSTOM_SSH_PORT"
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication no"
    echo "UsePAM yes"
    if [ "$SETUP_2FA" = true ]; then
        # Многошаговый диалог: пароль (pam_unix) + OTP (pam_google_authenticator)
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

# ssh.socket (Ubuntu 24.04) — настраиваем порт через override
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

# ─── 4. UFW ───────────────────────────────────────────────────────────────────
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

# ─── 5. Fail2ban ──────────────────────────────────────────────────────────────
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

# ─── 6. Аутентификация SSH (PAM) ──────────────────────────────────────────────
echo "=== [6/7] Аутентификация SSH (PAM) ==="

# 6.1. Генерируем 2FA ДО изменения PAM и ДО рестарта SSH.
#     Если файл не создастся — скрипт упадёт до рестарта, локаут невозможен.
if [ "$SETUP_2FA" = true ]; then
    echo ""
    echo "=========================================================="
    echo " ГЕНЕРАЦИЯ 2FA для пользователя $NEW_USER"
    echo " Отсканируйте QR-код в Google Authenticator / FreeOTP."
    echo " Сохраните аварийные коды!"
    echo "=========================================================="
    echo ""
    read -p "Нажмите Enter для генерации..."

    # sudo -u ... -i даёт полноценный login-env (корректный $HOME).
    # -f у google-authenticator = без интерактивных подтверждений.
    # QR-код может не отобразиться в non-TTY, но файл будет создан.
    sudo -u "$NEW_USER" -i bash -c 'google-authenticator -t -d -f -r 3 -R 30' || true

    GA_FILE="/home/$NEW_USER/.google_authenticator"
    if [ ! -s "$GA_FILE" ]; then
        echo -e "${RED}[-] ОШИБКА: $GA_FILE не создан или пуст. 2FA не заработает.${RESET}"
        echo "    Текущая SSH-сессия сохранена. Исправьте вручную и перезапустите скрипт."
        exit 1
    fi
    chmod 0600 "$GA_FILE"
    chown "$NEW_USER:$NEW_USER" "$GA_FILE"
    echo -e "${GREEN}[+] Файл 2FA: $GA_FILE (права 0600, владелец $NEW_USER).${RESET}"
fi

# 6.2. Настраиваем PAM
PAM_FILE="/etc/pam.d/sshd"
[ ! -f "${PAM_FILE}.hardening-backup" ] && cp "$PAM_FILE" "${PAM_FILE}.hardening-backup"

# Удаляем любые старые вхождения модуля OTP (идемпотентность)
sed -i '/pam_google_authenticator\.so/d' "$PAM_FILE"

if [ "$SETUP_2FA" = true ]; then
    # КОРНЕВОЕ ИСПРАВЛЕНИЕ:
    #   Модуль OTP должен стоять ПЕРЕД @include common-auth.
    #   Используем `i` (insert before), а не `a` (append after).
    #   При порядке "после" PAM завершает auth-стек после pam_unix,
    #   и до запроса OTP дело не доходит — ровно ваш симптом.
    sed -i '/^@include common-auth$/i auth required pam_google_authenticator.so' "$PAM_FILE"
    echo "[*] PAM настроен: OTP (pam_google_authenticator) → пароль (pam_unix)."
else
    echo "[*] 2FA отключён — вход только по паролю."
fi

# 6.3. Проверка синтаксиса sshd (защита от локаута)
echo "[*] Проверка синтаксиса sshd..."
mkdir -p /run/sshd && chmod 0755 /run/sshd
if ! sshd -t; then
    echo -e "${RED}[-] ОШИБКА: sshd -t провалился. Рестарт отменён.${RESET}"
    echo "    Восстановите ${PAM_FILE} из ${PAM_FILE}.hardening-backup при необходимости."
    exit 1
fi
echo -e "${GREEN}[+] sshd -t OK.${RESET}"

# 6.4. Показываем, что РЕАЛЬНО применится
echo ""
echo "=== Применяемая PAM-конфигурация ($PAM_FILE) ==="
grep -nE 'google_authenticator|common-auth' "$PAM_FILE" || true
echo ""
echo "=== Эффективная конфигурация sshd (sshd -T) ==="
sshd -T 2>/dev/null | grep -E '^(port|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|usepam|permitrootlogin|pubkeyauthentication) ' || true
echo ""

# 6.5. Предупреждение и рестарт
echo -e "${YELLOW}ВНИМАНИЕ: сейчас SSH будет перезапущен.${RESET}"
echo -e "${YELLOW}НЕ закрывайте текущую сессию. Проверьте вход в новом окне.${RESET}"
echo -e "  ssh -p $CUSTOM_SSH_PORT $NEW_USER@$SERVER_IP"
if [ "$SETUP_2FA" = true ]; then
    echo -e "  (должно запросить: 1) код 2FA, 2) пароль)"
fi
read -p "Нажмите Enter для рестарта SSH (Ctrl+C для отмены)..."

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

# ─── 7. Фоновое обслуживание ──────────────────────────────────────────────────
echo "=== [7/7] Фоновое обслуживание ==="

if [ "$SETUP_UNATTENDED" = true ]; then
    apt-get install -y unattended-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    grep -q 'Remove-Unused-Dependencies' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null \
        || echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e "${GREEN}[+] Автообновления включены.${RESET}"
fi

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
echo -e " Пользователь:  ${CYAN}$NEW_USER${RESET}"
echo -e " SSH порт:      ${CYAN}$CUSTOM_SSH_PORT${RESET}"
echo -e " IP-адрес:      ${CYAN}$SERVER_IP${RESET}"
if [ "$SETUP_2FA" = true ]; then
    echo -e " 2FA:           ${CYAN}Включена (ОTP → пароль)${RESET}"
else
    echo -e " 2FA:           ${CYAN}Выключена${RESET}"
fi
echo ""
echo -e " ${BOLD}Не закрывайте текущую сессию!${RESET}"
echo -e " Откройте НОВОЕ окно и проверьте вход:"
echo -e " ${BOLD}ssh -vvv -p $CUSTOM_SSH_PORT $NEW_USER@$SERVER_IP${RESET}"
if [ "$SETUP_2FA" = true ]; then
    echo -e " В выводе должно быть: ${CYAN}Next authentication method: keyboard-interactive${RESET}"
    echo -e " Затем два запроса: ${CYAN}Verification code${RESET}, потом ${CYAN}Password${RESET}"
fi
echo -e "${YELLOW}==========================================================${RESET}"
