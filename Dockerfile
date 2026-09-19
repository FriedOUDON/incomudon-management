FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/incomudon-management .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/incomudon-management /incomudon-management
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/incomudon-management"]