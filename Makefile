.PHONY: build test demo verify-demo guest host-check bench clean
build:
	go build -o bin/tracefuse ./cmd/tracefuse
test:
	go vet ./... && go test ./...
demo: build
	./scripts/demo.sh
verify-demo:
	./scripts/verify-demo.sh demo.log
host-check:
	./scripts/check-host.sh
guest:
	./guest/build-rootfs.sh
bench: build
	./scripts/bench.sh
clean:
	rm -rf bin .tracefuse
