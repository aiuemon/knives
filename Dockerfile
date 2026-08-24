FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
ARG TARGET
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/${TARGET}

FROM alpine:3.20 AS api
RUN apk add --no-cache ca-certificates
COPY --from=build /out/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]

FROM alpine:3.20 AS redirect
RUN apk add --no-cache ca-certificates
COPY --from=build /out/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]

FROM alpine:3.20 AS worker
RUN apk add --no-cache ca-certificates
COPY --from=build /out/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
