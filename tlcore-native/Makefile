.PHONY: build run vet clean

build:
	go build -mod=mod -o tlcore-native .

run: build
	./tlcore-native -addr 127.0.0.1:8080 -data ./data

vet:
	go vet ./...

clean:
	rm -f tlcore-native
	rm -rf data
