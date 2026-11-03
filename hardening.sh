#!/bin/bash

# Останавливать выполнение при любой ошибке
set -e

# Проверка, что скрипт запущен от root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Ошибка: Запустите этот скрипт с правами root (sudo ./bootstrap.sh)."
  exit 1
fi

echo "=========================================================="
echo " ИНТЕРАКТИВНАЯ НАСТРОЙКА БЕЗОПАСНОСТИ VPS (UBUNTU 24.04)"
echo "=========================================================="
echo ""

# 1. Интерактивный запрос данных
read -p "Введите имя нового sudo-пользователя [deploy]: " NEW_USER
NEW_USER=${NEW_USER:-deploy}

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

read -p "Введите дополнительные порты через пробел (например: 80 443 3000, или оставьте пустым): " EXTRA_PORTS

# Вопросы с выбором y/n (по умолчанию Y)
read -p "Устанавливать Fail2ban? [Y/n]: " SETUP_FAIL2BAN_INPUT
SETUP_FAIL2BAN_INPUT=${SETUP_FAIL2BAN_INPUT:-y}
if [[ "$SETUP_FAIL2BAN_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_FAIL2BAN=true
else
    SETUP_FAIL2BAN=false
fi

read -p "Настраивать Google Authenticator 2FA? [Y/n]: " SETUP_2FA_INPUT
SETUP_2FA_INPUT=${SETUP_2FA_INPUT:-y}
if [[ "$SETUP_2FA_INPUT" =~ ^[Yy]$ ]]; then
    SETUP_2FA=true
else
    SETUP_2FA=false
fi

echo ""
echo "=== [1/7] Обновление системы и установка утилит ==="
apt update && apt upgrade -y
apt install -y ufw curl git htop sudo

echo "=== [2/7] Создание пользователя $NEW_USER и настройка прав ==="
if id "$NEW_USER" &>/dev/null; then
    echo "[!] Пользователь $NEW_USER уже существует, обновляем пароль и права."
    # Безопасная передача пароля без интерполяции спецсимволов через printf
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
else
    adduser --gecos "" "$NEW_USER"
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
    usermod -aG sudo "$NEW_USER"
    echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$NEW_USER
    chmod 440 /etc/sudoers.d/$NEW_USER
fi
echo "[+] Пользователь $NEW_USER успешно настроен."

echo "=== [3/7] Настройка кастомного SSH порта и безопасности ==="
# Меняем порт и отключаем вход root в sshd_config
sed -i "s/^#\?Port .*/Port $CUSTOM_SSH_PORT/" /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Безупречная обработка ssh.socket для Ubuntu 24.04 (IPv4 + IPv6 Dual Stack)
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

# Явно блокируем почтовые порты (спам-векторы)
ufw deny 25/tcp
ufw deny 465/tcp
ufw deny 587/tcp
ufw deny 2525/tcp

# Открываем новый SSH порт
ufw allow "$CUSTOM_SSH_PORT/tcp"

# Открываем дополнительные пользовательские порты, если указаны
for port in $EXTRA_PORTS; do
    echo "[+] Открываем дополнительный порт: $port"
    ufw allow "$port"
done

ufw --force enable
echo "[+] UFW активирован. Почтовые порты заблокированы. Новый SSH порт: $CUSTOM_SSH_PORT."

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
    echo "[+] Fail2ban установлен, настроен под systemd и запущен."
else
    echo "=== [5/7] Пропуск установки Fail2ban ==="
fi

# Установка Google Authenticator по условию
if [ "$SETUP_2FA" = true ]; then
    echo "=== [6/7] Настройка Google Authenticator PAM ==="
    apt install -y libpam-google-authenticator
    
    echo ""
    echo "=========================================================="
    echo " ВНИМАНИЕ: Настройка 2FA для пользователя $NEW_USER"
    echo " Сейчас запустится мастер настройки Google Authenticator."
    echo " Отвечайте на вопросы (обычно 'y' для time-based, сохраните коды)."
    echo "=========================================================="
    echo ""
    read -p "Нажмите Enter, чтобы запустить мастер 2FA..."
    
    # Безопасный запуск в домашней директории с корректными парными флагами -r и -R
    runuser -u "$NEW_USER" -- bash -c 'cd ~ && google-authenticator -t -d -f -r 3 -R 30'
    
    # Интеграция модуля в /etc/pam.d/sshd (сразу после common-auth)
    if ! grep -q "pam_google_authenticator.so" /etc/pam.d/sshd; then
        sed -i '/@include common-auth/a auth required pam_google_authenticator.so' /etc/pam.d/sshd
    fi
    
    # Настройка OpenSSH для работы через keyboard-interactive
    sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    if grep -q "^AuthenticationMethods" /etc/ssh/sshd_config; then
        sed -i 's/^AuthenticationMethods.*/AuthenticationMethods keyboard-interactive/' /etc/ssh/sshd_config
    else
        echo "AuthenticationMethods keyboard-interactive" >> /etc/ssh/sshd_config
    fi
    
    systemctl restart ssh.socket || true
    systemctl restart ssh || true
    echo "[+] Google Authenticator успешно настроен!"
else
    echo "=== [6/7] Пропуск настройки Google Authenticator ==="
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
    systemctl restart ssh.socket || true
    systemctl restart ssh || true
fi

echo "=== [7/7] Финальная проверка служб ==="
systemctl daemon-reload
systemctl restart ssh.socket || true
systemctl restart ssh || true

echo ""
echo "=========================================================="
echo " СЕРВЕР УСПЕШНО НАСТРОЕН И ЗАЩИЩЕН!"
echo " Новый пользователь: $NEW_USER"
echo " Новый SSH порт: $CUSTOM_SSH_PORT"
echo " Метод входа: Интерактивный (Пароль + Google Authenticator)"
echo " Подключайтесь командой:"
echo " ssh -p $CUSTOM_SSH_PORT $NEW_USER@<IP_АДРЕС>"
echo "=========================================================="
