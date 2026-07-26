---
title: 03. gRPC Attack Scenarios & Multi-Language Code Examples
description: Production code examples comparing vulnerable vs secure gRPC implementations
  across Go, Python, Node.js, and Java.
keywords:
- gRPC
- Code
- Examples
- Vulnerable
- vs
- Secure
- Go
- gRPC
- Python
- gRPC
- Node
- js
- gRPC
- Java
- gRPC
- Interceptors
- mTLS
slug: /web-and-api/grpc-security/code-examples
---


# 03. gRPC Attack Scenarios & Multi-Language Code Examples

This chapter provides robust, production-grade code examples illustrating vulnerable vs secure patterns across four major backend languages: **Go**, **Python**, **Node.js**, and **Java**.

---

## 1. Go (Golang) Implementation

### ❌ Vulnerable Go gRPC Server Setup
```go
package main

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	pb "example.com/user/pb"
)

type UserServer struct {
	pb.UnimplementedUserServiceServer
}

// VULNERABLE: No authorization check, vulnerable to BOLA / IDOR!
func (s *UserServer) GetUserProfile(ctx context.Context, req *pb.GetUserRequest) (*pb.UserProfile, error) {
	// Directly fetches profile using user-supplied ID without verifying caller identity!
	return &pb.UserProfile{
		UserId: req.GetUserId(),
		Email:  "victim@example.com",
		Role:   "User",
	}, nil
}

func main() {
	lis, _ := net.Listen("tcp", ":50051")

	// VULNERABLE 1: Plaintext transport (No TLS/mTLS)
	s := grpc.NewServer()

	pb.RegisterUserServiceServer(s, &UserServer{})

	// VULNERABLE 2: Server Reflection unconditionally enabled in production!
	reflection.Register(s)

	fmt.Println("Vulnerable gRPC server running on :50051...")
	s.Serve(lis)
}
```

### ✅ Secure Hardened Go gRPC Server Setup
```go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/reflection"

	pb "example.com/user/pb"
)

// SECURE: Interceptor for JWT Metadata Authentication & AuthZ
func UnaryAuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "Missing request metadata")
	}

	tokens := md["authorization"]
	if len(tokens) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "Missing authorization token")
	}

	token := tokens[0]
	claims, err := validateJWT(token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid authentication token: %v", err)
	}

	// Attach authenticated caller identity to context
	newCtx := context.WithValue(ctx, "authenticated_user_id", claims.UserID)
	return handler(newCtx, req)
}

type HardenedUserServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *HardenedUserServer) GetUserProfile(ctx context.Context, req *pb.GetUserRequest) (*pb.UserProfile, error) {
	authUserID, ok := ctx.Value("authenticated_user_id").(string)
	if !ok || authUserID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "Unauthenticated context")
	}

	// SECURE: Enforce BOLA protection by ensuring users can only access their own data
	if req.GetUserId() != authUserID {
		return nil, status.Errorf(codes.PermissionDenied, "Access denied to requested resource")
	}

	return &pb.UserProfile{
		UserId: authUserID,
		Email:  "user@example.com",
	}, nil
}

func loadmTLSCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)

	// SECURE: TLS 1.3 + Require mTLS client cert verification
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(config), nil
}

func main() {
	tlsCreds, err := loadmTLSCredentials()
	if err != nil {
		panic(err)
	}

	lis, _ := net.Listen("tcp", ":50051")

	// SECURE: Bind mTLS credentials & Auth Interceptor
	s := grpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.UnaryInterceptor(UnaryAuthInterceptor),
	)

	pb.RegisterUserServiceServer(s, &HardenedUserServer{})

	// SECURE: Enable Reflection ONLY in non-production environments
	if os.Getenv("ENV") == "development" {
		reflection.Register(s)
	}

	s.Serve(lis)
}
```

---

## 2. Python (`grpcio`) Implementation

### ❌ Vulnerable Python gRPC Server Setup
```python
import grpc
from concurrent import futures
import user_pb2
import user_pb2_grpc
from grpc_reflection.v1alpha import reflection

class UserService(user_pb2_grpc.UserServiceServicer):
    # VULNERABLE: Unchecked input & missing authentication interceptor
    def TransferFunds(self, request, context):
        # Vulnerable to negative transfers (integer manipulation)
        sender = request.sender_id
        recipient = request.recipient_id
        amount = request.amount # Negative amount adds balance!
        
        return user_pb2.TransferResponse(success=True, message=f"Transferred ${amount}")

def serve():
    # VULNERABLE 1: Plaintext server without TLS
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    user_pb2_grpc.add_UserServiceServicer_to_server(UserService(), server)
    
    # VULNERABLE 2: Reflection unconditionally exposed
    SERVICE_NAMES = (
        user_pb2.DESCRIPTOR.services_by_name['UserService'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)
    
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()
```

### ✅ Secure Hardened Python gRPC Server Setup
```python
import grpc
import os
from concurrent import futures
import user_pb2
import user_pb2_grpc

class AuthInterceptor(grpc.ServerInterceptor):
    def __init__(self):
        def deny(context, details):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, details)
        self._deny = deny

    def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata)
        auth_header = metadata.get('authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return self._deny(handler_call_details, "Missing or malformed authorization metadata")

        token = auth_header.split('Bearer ')[1]
        user_id = self._verify_token(token)
        if not user_id:
            return self._deny(handler_call_details, "Invalid token")

        return continuation(handler_call_details)

    def _verify_token(self, token):
        # Cryptographic verification logic (e.g. PyJWT verification)
        return "user_123" if token == "valid-secret-token" else None

class HardenedUserService(user_pb2_grpc.UserServiceServicer):
    def TransferFunds(self, request, context):
        # SECURE: Strict input validation on message fields
        if request.amount <= 0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Transfer amount must be strictly positive")
        
        if not request.recipient_id or len(request.recipient_id) > 64:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid recipient identifier")

        return user_pb2.TransferResponse(success=True, message="Transfer processed securely")

def serve_secure():
    # SECURE: Configure mTLS with server key, cert, and client CA pool
    with open('server.key', 'rb') as f:
        private_key = f.read()
    with open('server.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('ca.crt', 'rb') as f:
        root_certificates = f.read()

    server_credentials = grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True # Enforce mTLS
    )

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=(AuthInterceptor(),),
        options=[
            ('grpc.max_concurrent_streams', 100), # Enforce stream limits against DoS
            ('grpc.max_receive_message_length', 4 * 1024 * 1024) # 4MB limit
        ]
    )
    user_pb2_grpc.add_UserServiceServicer_to_server(HardenedUserService(), server)
    server.add_secure_port('[::]:50051', server_credentials)
    server.start()
    server.wait_for_termination()
```

---

## 3. Node.js (`@grpc/grpc-js`) Implementation

### ❌ Vulnerable Node.js gRPC Server Setup
```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const packageDefinition = protoLoader.loadSync('user.proto');
const userProto = grpc.loadPackageDefinition(packageDefinition).user;

function getUser(call, callback) {
  // VULNERABLE: No authorization check, directly returns sensitive details
  callback(null, { userId: call.request.userId, email: "admin@company.com", is_admin: true });
}

const server = new grpc.Server();
userProto.UserService.service;

// VULNERABLE: Plaintext server without TLS or interceptors
server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), (err, port) => {
  if (!err) server.start();
});
```

### ✅ Secure Hardened Node.js gRPC Server Setup
```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const fs = require('fs');

const packageDefinition = protoLoader.loadSync('user.proto', {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});
const userProto = grpc.loadPackageDefinition(packageDefinition).user;

// SECURE: Middleware Interceptor for Bearer Token Validation
function authMiddleware(call, callback, next) {
  const metadata = call.metadata.get('authorization');
  if (!metadata || metadata.length === 0) {
    return callback({
      code: grpc.status.UNAUTHENTICATED,
      details: 'Missing Authorization Metadata'
    });
  }

  const token = metadata[0].replace('Bearer ', '');
  if (token !== process.env.EXPECTED_TOKEN) {
    return callback({
      code: grpc.status.UNAUTHENTICATED,
      details: 'Invalid Authorization Token'
    });
  }

  next();
}

function getUserSecure(call, callback) {
  // Enforce field validation
  const userId = call.request.userId;
  if (!userId || typeof userId !== 'string' || userId.length > 36) {
    return callback({
      code: grpc.status.INVALID_ARGUMENT,
      details: 'Invalid UserId payload format'
    });
  }

  callback(null, { userId: userId, email: "user@example.com" });
}

// Load mTLS certificates
const serverCredentials = grpc.ServerCredentials.createSsl(
  fs.readFileSync('ca.crt'),
  [{
    private_key: fs.readFileSync('server.key'),
    cert_chain: fs.readFileSync('server.crt')
  }],
  true // SECURE: Require client certificate verification (mTLS)
);

const server = new grpc.Server();
server.addService(userProto.UserService.service, {
  getUser: (call, callback) => {
    authMiddleware(call, callback, () => getUserSecure(call, callback));
  }
});

server.bindAsync('0.0.0.0:50051', serverCredentials, (err, port) => {
  if (err) throw err;
  console.log(`Hardened Node.js gRPC Server running with mTLS on port ${port}`);
});
```

---

## 4. Java (`grpc-java`) Implementation

### ❌ Vulnerable Java gRPC Server Setup
```java
package com.example.grpc;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;

public class VulnerableUserServer {
    public static void main(String[] args) throws Exception {
        // VULNERABLE: Plaintext server using usePlaintext()
        Server server = ServerBuilder.forPort(50051)
            .addService(new UserServiceImpl())
            .build()
            .start();
        
        System.out.println("Vulnerable Java gRPC server started on port 50051...");
        server.awaitTermination();
    }

    static class UserServiceImpl extends UserServiceGrpc.UserServiceImplBase {
        @Override
        public void getUser(UserRequest req, StreamObserver<UserResponse> responseObserver) {
            // VULNERABLE: No authentication or authorization interceptor registered!
            UserResponse response = UserResponse.newBuilder()
                .setUserId(req.getUserId())
                .setEmail("vulnerable@example.com")
                .build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }
}
```

### ✅ Secure Hardened Java gRPC Server Setup
```java
package com.example.grpc;

import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;

import java.io.File;

public class SecureUserServer {

    // SECURE: Java ServerInterceptor for Metadata Authorization
    private static class HeaderAuthInterceptor implements ServerInterceptor {
        private static final Metadata.Key<String> AUTH_KEY =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
            
            String authHeader = headers.get(AUTH_KEY);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                call.close(Status.UNAUTHENTICATED.withDescription("Missing authorization header"), headers);
                return new ServerCall.Listener<ReqT>() {};
            }

            String token = authHeader.substring(7);
            if (!isValidToken(token)) {
                call.close(Status.UNAUTHENTICATED.withDescription("Invalid JWT Token"), headers);
                return new ServerCall.Listener<ReqT>() {};
            }

            return next.startCall(call, headers);
        }

        private boolean isValidToken(String token) {
            return "secret-java-token".equals(token);
        }
    }

    public static void main(String[] args) throws Exception {
        // SECURE: Configure TLS 1.3 mTLS via SslContextBuilder
        SslContext sslContext = GrpcSslContexts.forServer(
                new File("server.crt"), new File("server.key"))
            .trustManager(new File("ca.crt"))
            .clientAuth(ClientAuth.REQUIRE) // Enforce mTLS
            .build();

        Server server = NettyServerBuilder.forPort(50051)
            .sslContext(sslContext)
            .intercept(new HeaderAuthInterceptor()) // Enforce Auth Interceptor
            .addService(new UserServiceImpl())
            .build()
            .start();

        System.out.println("Hardened Java gRPC server running with mTLS on port 50051...");
        server.awaitTermination();
    }

    static class UserServiceImpl extends UserServiceGrpc.UserServiceImplBase {
        @Override
        public void getUser(UserRequest req, StreamObserver<UserResponse> responseObserver) {
            // SECURE: Input validation
            if (req.getUserId() <= 0) {
                responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription("UserId must be greater than zero")
                    .asRuntimeException());
                return;
            }

            UserResponse response = UserResponse.newBuilder()
                .setUserId(req.getUserId())
                .setEmail("user@example.com")
                .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }
}
```

---

*Next Chapter: [04. Production Defenses & gRPC Hardening →](04-defenses.md)*
