.PHONY: run
run:
	@echo "Running..."
	env $$(cat .env | xargs) go run ./app/main.go
