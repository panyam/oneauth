.PHONY: up down logs rebuild clean

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

rebuild:
	docker compose up -d --build --force-recreate

clean:
	docker compose down -v

status:
	@echo "OneAuth Server: http://localhost:9999"
	@echo "DrawApp:        http://localhost:3001"
	@echo "ChatApp:        http://localhost:3002"
	@echo "Relay-A:        http://localhost:4001"
	@echo "Relay-B:        http://localhost:4002"
	@echo ""
	@docker compose ps
