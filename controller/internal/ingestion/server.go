package ingestion

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

// Server wraps the gRPC server with lifecycle management.
type Server struct {
	grpcServer *grpc.Server
	handler    *GRPCHandler
	listener   net.Listener
}

func NewServer(handler *GRPCHandler) *Server {
	srv := grpc.NewServer()
	pb.RegisterXSightServiceServer(srv, handler)
	return &Server{
		grpcServer: srv,
		handler:    handler,
	}
}

// Serve starts the gRPC server on the given address. Blocks until stopped.
func (s *Server) Serve(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", addr, err)
	}
	s.listener = lis
	log.Printf("grpc: listening on %s", addr)
	return s.grpcServer.Serve(lis)
}

// GracefulStop performs a graceful shutdown.
func (s *Server) GracefulStop() {
	log.Println("grpc: graceful stop")
	s.grpcServer.GracefulStop()
}

// Handler returns the underlying GRPCHandler.
func (s *Server) Handler() *GRPCHandler {
	return s.handler
}
