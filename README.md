# GoAuthService
Реализация части сервиса авторизации с примененим JWT и refresh/access токенов

## Установка и запуск

```bash
# Склонируйте репозиторий
git clone https://github.com/v1adis1av28/GoAuthService.git
# Перейдите в директорию с докером для запуска
cd GoAuthService && cd docker

# Запуск сервиса
docker-compose -f docker-compose.yml up -d
```

Сервис будет доступен по адресу: [http://localhost:8080](http://localhost:8080)

Документация Swagger по адресу: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

---

## API Endpoints

### Основные endpoint'ы:

| Метод  | Путь         | Описание                        | Требует Auth |
|--------|--------------|----------------------------------|---------------|
| GET    | `/token`     | Получить пару токенов            | Нет           |
| POST   | `/refresh`   | Обновить пару токенов            | Да (Bearer)   |
| GET    | `/guid`      | Получить GUID пользователя       | Да (Bearer)   |
| POST   | `/logout`    | Деавторизовать пользователя      | Да (Bearer)   |
| POST   | `/changeIp`  | Webhook для изменения IP (внутр.)| Нет           |

---


### База данных:

Используется PostgreSQL с следующими таблицей пользователей:

- `users`: содержит `GUID`, `refresh_token_hash`, `last_ip`
