#!/bin/bash

set -e

echo "=== [1/5] Обновление пакетов Termux ==="
pkg update -y
pkg upgrade -y

echo "=== [2/5] Установка системных утилит (Python, pip, sing-box, termux-api) ==="
pkg install -y python python-pip sing-box termux-api git

echo "=== [3/5] Запрос прав на доступ к памяти ==="
echo "[i] Если появится всплывающее окно — разрешите доступ к файлам!"
termux-setup-storage
sleep 2

echo "=== [4/5] Создание директории для ссылок ==="
mkdir -p /storage/emulated/0/links

echo "=== [5/5] Установка зависимостей Python ==="

if [ -f "requirements.txt" ]; then
    python -m pip install --break-system-packages -r requirements.txt
else
    python -m pip install --break-system-packages rich requests
fi

echo ""
echo "=================================================="
echo "  Установка успешно завершена! 🎉"
echo "=================================================="
echo ""

read -p "Скачать списки ссылок прямо сейчас? (y/n, По умолчанию: y): " ANSWER

ANSWER=$(echo "$ANSWER" | tr '[:upper:]' '[:lower:]')

if [[ -z "$ANSWER" || "$ANSWER" == "y" || "$ANSWER" == "yes" || "$ANSWER" == "д" || "$ANSWER" == "да" ]]; then
    echo ""
    echo "[*] Запуск обновления списков (update.py)..."
    python update.py
else
    echo ""
    echo "[*] Пропуск скачивания."
    echo "[i] Позже можно запустить:"
    echo ""
    echo "    python update.py"
    echo ""
    exit 0
fi