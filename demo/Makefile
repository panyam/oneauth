.PHONY: dev up down logs rebuild clean reset

# Live-reload development (PG in Docker, everything else native)
dev:
	devloop

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

# Reset all demo state: stop containers, remove volumes, delete local data
reset:
	docker compose down -v
	rm -rf ./data

status:
	@echo "OneAuth Server: http://localhost:9999"
	@echo "DrawApp:        http://localhost:3001"
	@echo "ChatApp:        http://localhost:3002"
	@echo "Resource Srv A: http://localhost:4001"
	@echo "Resource Srv B: http://localhost:4002"
	@echo ""
	@docker compose ps
