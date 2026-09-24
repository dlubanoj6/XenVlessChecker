#!/bin/bash

set -e

echo "=== [1/5] Обновление пакетов Termux ==="
pkg update -y && pkg upgrade -y

echo "=== [2/5] Установка системных утилит (Python, sing-box, termux-api) ==="
pkg install -y python sing-box termux-api git

echo "=== [3/5] Запрос прав на доступ к памяти ==="
echo "[i] Если появится всплывающее окно — разрешите доступ к файлам!"
termux-setup-storage
sleep 2

echo "=== [4/5] Создание директории для ссылок ==="
mkdir -p /storage/emulated/0/links

echo "=== [5/5] Установка зависимостей Python ==="
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install rich requests
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
    echo "[*] Пропуск скачивания. Вы можете запустить его позже командой: python update.py"
    exit 0
fi
