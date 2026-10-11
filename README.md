# Tross

Домашний мульти-WAN балансир для мини-ПК на Debian: несколько интернет-каналов
(два проводных провайдера и LTE) работают как один надёжный «трос».
Балансировка по соединениям, отказоустойчивость, SQM (CAKE), собственный
DNS-резолвер, обход DPI (zapret) и прокси (mihomo) для доменов из списков.

Статус: **Этап 0 — фундамент**. Демон запускается только в «сухом» режиме
(ничего не меняет в системе). Все поля конфигурации с пояснениями — в
[configs/example.yaml](configs/example.yaml).

## Сборка

Нужен Go 1.26+.

```sh
make build         # bin/trossd для текущей ОС
make build-linux   # bin/linux-amd64/trossd, статический
make test
make lint          # gofmt, go vet (хост и linux), staticcheck
```

## Лицензия

Tross распространяется под [GNU General Public License v3.0](LICENSE).
Сторонние компоненты, которые демон запускает отдельными программами
(mihomo, zapret), — под собственными лицензиями.

## Запуск в «сухом» режиме

```sh
./bin/trossd -config configs/example.yaml -dry-run
curl http://127.0.0.1:8080/api/health
curl http://127.0.0.1:8080/api/links
```
