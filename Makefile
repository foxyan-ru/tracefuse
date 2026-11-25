.PHONY: build test demo guest bench clean
build:
	go build -o bin/tracefuse ./cmd/tracefuse
test:
	go vet ./... && go test ./...
demo: build
	./scripts/demo.sh
guest:
	./guest/build-rootfs.sh
bench: build
	./scripts/bench.sh
clean:
	rm -rf bin .tracefuse
