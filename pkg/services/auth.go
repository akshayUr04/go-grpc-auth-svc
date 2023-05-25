package services

import (
	"context"
	"fmt"
	"net/http"

	"github.com/akshayUr04/go-grpc-auth-svc/pkg/db"
	"github.com/akshayUr04/go-grpc-auth-svc/pkg/models"
	"github.com/akshayUr04/go-grpc-auth-svc/pkg/pb"
	"github.com/akshayUr04/go-grpc-auth-svc/pkg/utils"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
	pb.UnimplementedAuthServiceServer
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	fmt.Println("---Register---")
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error == nil {
		return &pb.RegisterResponse{
			Status: http.StatusConflict,
			Error:  "E-Mail already exists",
		}, nil
	}
	user.Email = req.Email
	user.Password = utils.HashPassword(req.Password)

	s.H.DB.Create(&user)

	return &pb.RegisterResponse{
		Status: http.StatusCreated,
	}, nil
}

func (s *Server) AdminRegister(ctx context.Context, req *pb.AdminRegisterRequest) (*pb.AdminRegisterResponse, error) {
	fmt.Println("---AdminRegister---")
	var admin models.Admin

	if result := s.H.DB.Where(&models.Admin{Email: req.Email}).First(&admin); result.Error == nil {
		return &pb.AdminRegisterResponse{
			Status: http.StatusConflict,
			Error:  "E-Mail already exists",
		}, nil
	}

	admin.Email = req.Email
	admin.Password = utils.HashPassword(req.Password)
	fmt.Println(admin.Password)
	s.H.DB.Create(&admin)

	return &pb.AdminRegisterResponse{
		Status: http.StatusCreated,
	}, nil
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	fmt.Println("---Login---")
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error != nil {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)

	if !match {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	token, err := s.Jwt.GenerateToken(user)
	if err != nil {
		return &pb.LoginResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, err
	}

	return &pb.LoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}
func (s *Server) AdminLogin(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	fmt.Println("---AdminLogin---")
	var admin models.Admin
	findUserQuery := `SELECT * FROM admins WHERE email=$1`
	if err := s.H.DB.Raw(findUserQuery, req.Email).Scan(&admin).Error; err != nil {
		return &pb.AdminLoginResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, err
	}
	match := utils.CheckPasswordHash(req.Password, admin.Password)
	if !match {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "Admin not found",
		}, nil
	}
	token, err := s.Jwt.GenerateAdminToken(admin)
	if err != nil {
		return &pb.AdminLoginResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, err
	}
	return &pb.AdminLoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}
func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	fmt.Println("---Validate---")
	claims, err := s.Jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, err
	}

	var user models.User

	if result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); result.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserId: user.Id,
	}, nil

}
