up:
	docker-compose up --build -d

down:
	docker-compose down

build:
	docker-compose build --pull

logs:
	docker-compose logs -f
