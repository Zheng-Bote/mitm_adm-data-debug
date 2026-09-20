#!/usr/bin/sh

# Handle missing git tags gracefully
MITM_VERSION=$(git describe --tags 2>/dev/null || echo "v0.1.0-dev")

mkdir -p bin

# CGO_ENABLED=1 is required for Fyne (due to OpenGL/X11 dependencies)
CGO_ENABLED=1 go build -ldflags="-s -w -X main.version=${MITM_VERSION}" -o ./bin/mitm-adm-data .

mkdir -p ../../scheduler/mitm_scheduler/bin
cp bin/mitm-adm-data ../../scheduler/mitm_scheduler/bin/.
