docker-compose-build:
	docker-compose build

docker-compose-up:
	docker-compose up

docker-compose-down:
	docker-compose down

unit-tests:
	go test -v ./...

api-tests:
	pytest

godoc:
	godoc -http=:6060 &