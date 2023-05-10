proto:
		protoc pkg/pb/*.proto --go-grpc_out=. --go_out=. 
server:
	go run cmd/main.go	