#!/bin/bash

# Останавливать выполнение при любой ошибке
set -e

# Отключаем интерактивные диалоги установщика (избегаем зависаний)
export DEBIAN_FRONTEND=noninteractive

# Проверка, что скрипт запущен от root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Ошибка: Запустите этот скрипт с правами root (sudo ./hardening.sh)."
  exit 1
fi

echo "=========================================================="
echo " ИНТЕРАКТИВНАЯ НАСТРОЙКА И УПРАВЛЕНИЕ БЕЗОПАСНОСТЬЮ VPS"
echo " (UBUNTU 24.04 | PASSWORD + OPTIONAL GOOGLE AUTHENTICATOR)"
echo "=========================================================="
echo ""

# 1. Интерактивный запрос данных
read -p "Введите имя нового sudo-пользователя [deploy]: " NEW_USER
NEW_USER=${NEW_USER:-deploy}

if [ "$NEW_USER" = "root" ]; then
  echo "[-] Ошибка: Использование имени 'root' в качестве нового пользователя запрещено в целях безопасности."
  exit 1
fi

while true; do
    read -s -p "Введите пароль для пользователя $NEW_USER: " NEW_USER_PASSWORD
    echo
    read -s -p "Повторите пароль: " NEW_USER_PASSWORD_CONFIRM
    echo
    if [ "$NEW_USER_PASSWORD" = "$NEW_USER_PASSWORD_CONFIRM" ] && [ -n "$NEW_USER_PASSWORD" ]; then
        break
    else
        echo "[-] Пароли не совпадают или пусты. Попробуйте снова."
    fi
done

read -p "Введите новый порт для SSH [43780]: " CUSTOM_SSH_PORT
CUSTOM_SSH_PORT=${CUSTOM_SSH_PORT:-43780}

# Умное автоопределение внешнего IP-адреса
AUTO_IP=$(curl -4 -s --connect-timeout 2 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
read -p "Введите внешний IP-адрес сервера [${AUTO_IP:-не определен}]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$AUTO_IP}

read -p "Введите дополнительные порты через пробел (например: 80 443 3000, или оставьте пустым): " EXTRA_PORTS

# Опциональные вопросы конфигурации (единый стиль [y/n])
read -p "Устанавливать Fail2ban? [y/n]: " SETUP_FAIL2BAN_INPUT
SETUP_FAIL2BAN_INPUT=${SETUP_FAIL2BAN_INPUT:-y}
if [[ "$SETUP_FAIL2BAN_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_FAIL2BAN=true
else
    SETUP_FAIL2BAN=false
fi

read -p "Настраивать Google Authenticator 2FA? [y/n]: " SETUP_2FA_INPUT
SETUP_2FA_INPUT=${SETUP_2FA_INPUT:-y}
if [[ "$SETUP_2FA_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_2FA=true
else
    SETUP_2FA=false
fi

read -p "Включить unattended-upgrades (авто-обновления безопасности)? [y/n]: " SETUP_UNATTENDED_INPUT
SETUP_UNATTENDED_INPUT=${SETUP_UNATTENDED_INPUT:-y}
if [[ "$SETUP_UNATTENDED_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_UNATTENDED=true
else
    SETUP_UNATTENDED=false
fi

read -p "Настроить ежедневный Logwatch (с сохранением в файлы и очисткой >30 дней)? [y/n]: " SETUP_LOGWATCH_INPUT
SETUP_LOGWATCH_INPUT=${SETUP_LOGWATCH_INPUT:-y}
if [[ "$SETUP_LOGWATCH_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_LOGWATCH=true
else
    SETUP_LOGWATCH=false
fi

read -p "Включить авто-очистку диска при нехватке места (<15% свободно)? [y/n]: " SETUP_CLEANUP_INPUT
SETUP_CLEANUP_INPUT=${SETUP_CLEANUP_INPUT:-y}
if [[ "$SETUP_CLEANUP_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_CLEANUP=true
else
    SETUP_CLEANUP=false
fi

echo ""
echo "=== [1/7] Обновление системы, очистка и установка базовых утилит ==="
apt update && apt upgrade -y && apt autoremove -y
apt install -y ufw curl git htop sudo cron

# Устанавливаем пакет 2FA только если пользователь согласился
if [ "$SETUP_2FA" = true ]; then
    apt install -y libpam-google-authenticator
fi

echo "=== [2/7] Создание пользователя $NEW_USER и настройка прав ==="
if id "$NEW_USER" &>/dev/null; then
    echo "[!] Пользователь $NEW_USER уже существует, обновляем пароль."
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
else
    adduser --gecos "" "$NEW_USER"
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
    usermod -aG sudo "$NEW_USER"
fi

# Гарантированное создание правил sudoers с правильными правами 0440
echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$NEW_USER
chmod 440 /etc/sudoers.d/$NEW_USER
echo "[+] Пользователь $NEW_USER успешно настроен."

echo "=== [3/7] Настройка кастомного SSH порта и отключение ключей ==="

# Функция безопасного обновления параметров в sshd_config
set_sshd_param() {
    local param="$1"
    local value="$2"
    if grep -q "^#\? \?$param " /etc/ssh/sshd_config; then
        sed -i "s/^#\? \?$param .*/$param $value/" /etc/ssh/sshd_config
    else
        echo "$param $value" >> /etc/ssh/sshd_config
    fi
}

set_sshd_param "Port" "$CUSTOM_SSH_PORT"
set_sshd_param "PermitRootLogin" "no"
set_sshd_param "PubkeyAuthentication" "no"

# Обработка ssh.socket для Ubuntu 24.04 (IPv4 + IPv6 Dual Stack)
if systemctl list-unit-files | grep -q ssh.socket; then
    echo "[*] Обнаружен ssh.socket (Ubuntu 24.04+). Настраиваем systemd override для порта $CUSTOM_SSH_PORT..."
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat <<EOF > /etc/systemd/system/ssh.socket.d/override.conf
[Socket]
ListenStream=
ListenStream=0.0.0.0:$CUSTOM_SSH_PORT
ListenStream=[::]:$CUSTOM_SSH_PORT
EOF
    systemctl daemon-reload
    systemctl restart ssh.socket
else
    echo "[*] Используется стандартный sshd сервис."
    systemctl restart ssh
fi

echo "=== [4/7] Настройка UFW (Firewall) и блокировка почтовых портов ==="
ufw default deny incoming
ufw default allow outgoing

# Блокируем спам-векторы почты
ufw deny 25/tcp
ufw deny 465/tcp
ufw deny 587/tcp
ufw deny 2525/tcp

# Открываем новый SSH порт и кастомные порты
ufw allow "$CUSTOM_SSH_PORT/tcp"
for port in $EXTRA_PORTS; do
    echo "[+] Открываем дополнительный порт: $port"
    ufw allow "$port"
done

ufw --force enable
echo "[+] UFW активирован. Новый SSH порт: $CUSTOM_SSH_PORT."

# Установка Fail2ban по условию
if [ "$SETUP_FAIL2BAN" = true ]; then
    echo "=== [5/7] Установка и настройка Fail2ban ==="
    apt install -y fail2ban
    cat <<EOF > /etc/fail2ban/jail.local
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
    echo "[+] Fail2ban успешно настроен и запущен."
else
    echo "=== [5/7] Пропуск установки Fail2ban ==="
fi

echo "=== [6/7] Настройка аутентификации SSH ==="
if [ "$SETUP_2FA" = true ]; then
    if ! grep -q "pam_google_authenticator.so" /etc/pam.d/sshd; then
        sed -i '/@include common-auth/a auth required pam_google_authenticator.so' /etc/pam.d/sshd
    fi
    
    set_sshd_param "KbdInteractiveAuthentication" "yes"
    set_sshd_param "PasswordAuthentication" "yes"
    
    systemctl restart ssh.socket || true
    systemctl restart ssh || true

    echo ""
    echo "=========================================================="
    echo " ВНИМАНИЕ: Интерактивная генерация 2FA для пользователя $NEW_USER"
    echo " Сейчас появится QR-код. Отсканируйте его в Google Authenticator"
    echo " или FreeOTP на вашем смартфоне. Сохраните аварийные коды!"
    echo "=========================================================="
    echo ""
    read -p "Нажмите Enter для генерации секретного ключа 2FA..."
    
    # Запуск мастера генерации 2FA с полноценной инициализацией окружения пользователя
    su - "$NEW_USER" -c 'google-authenticator -t -d -f -r 3 -R 30'
else
    echo "[*] Режим без 2FA: включен вход только по паролю."
    set_sshd_param "KbdInteractiveAuthentication" "no"
    set_sshd_param "PasswordAuthentication" "yes"
fi

echo "=== [7/7] Настройка фоновых служб (Unattended-upgrades, Logwatch, Диск) ==="

# 1. Unattended-upgrades
if [ "$SETUP_UNATTENDED" = true ]; then
    apt install -y unattended-upgrades
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
    echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo "[+] Автоматические обновления безопасности включены."
fi

# 2. Logwatch с фиксированным PATH, автоочисткой временных файлов и сохранением в файл
if [ "$SETUP_LOGWATCH" = true ]; then
    apt install -y logwatch
    mkdir -p /var/log/logwatch_reports
    
    cat << 'EOF' > /etc/cron.daily/custom-logwatch
#!/bin/bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
REPORT_DIR="/var/log/logwatch_reports"
mkdir -p "$REPORT_DIR"

# Превентивно удаляем старые временные папки logwatch от возможных прошлых сбоев
rm -rf /tmp/logwatch.*

logwatch --output file --filename "$REPORT_DIR/report_$(date +%Y-%m-%d).txt" --range yesterday --detail med
find "$REPORT_DIR" -type f -mtime +30 -delete
EOF
    chmod +x /etc/cron.daily/custom-logwatch
    echo "[+] Logwatch настроен (хранение отчетов 30 дней)."
fi

# 3. Мониторинг и очистка диска (<15% свободного места)
if [ "$SETUP_CLEANUP" = true ]; then
    cat << 'EOF' > /usr/local/bin/vps-disk-cleanup.sh
#!/bin/bash
FREE_PERCENT=$(df / --output=pcent | tail -1 | tr -d ' %')
if [ "$FREE_PERCENT" -gt 85 ]; then
    apt-get clean -y
    journalctl --vacuum-time=7d
    rm -rf /tmp/* /var/tmp/*
fi
EOF
    chmod +x /usr/local/bin/vps-disk-cleanup.sh
    
    echo "0 3 * * * root /usr/local/bin/vps-disk-cleanup.sh" > /etc/cron.d/vps-disk-cleanup
    chmod 644 /etc/cron.d/vps-disk-cleanup
    echo "[+] Автоочистка диска настроена."
fi

# Финальный рестарт служб
systemctl daemon-reload
systemctl restart ssh.socket || true
systemctl restart ssh || true

# Определение цветов для красивого вывода
GREEN="\033[32m"
BOLD="\033[1m"
CYAN="\033[36m"
YELLOW="\033[33m"
RESET="\033[0m"

echo -e ""
echo -e "${YELLOW}==========================================================${RESET}"
echo -e "${GREEN}${BOLD} СЕРВЕР УСПЕШНО НАСТРОЕН!${RESET}"
echo -e " Новый пользователь: ${CYAN}$NEW_USER${RESET}"
echo -e " Новый SSH порт: ${CYAN}$CUSTOM_SSH_PORT${RESET}"
echo -e " IP-адрес сервера: ${CYAN}$SERVER_IP${RESET}"
echo -e " Двухфакторная аутентификация (2FA): ${CYAN}$([ "$SETUP_2FA" = true ] && echo "Включена" || echo "Выключена")${RESET}"
echo -e ""
echo -e " Подключайтесь командой:"
echo -e " ${BOLD}ssh -p $CUSTOM_SSH_PORT $NEW_USER@$SERVER_IP${RESET}"
if [ "$SETUP_2FA" = true ]; then
    echo -e " (Запросит пароль, а затем 6-значный код из приложения на телефоне)"
else
    echo -e " (Запросит только пароль пользователя)"
fi
echo -e "${YELLOW}==========================================================${RESET}"
