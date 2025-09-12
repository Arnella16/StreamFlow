package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"username"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"-" bson:"password"` // Hide password in JSON responses
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	LastLogin time.Time          `json:"lastLogin" bson:"lastLogin"`
}

// UserRequest represents the user registration/login request
type UserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents the login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// JWT Claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// DatabaseService encapsulates database operations
type DatabaseService struct {
	usersCollection *mongo.Collection
	logger          *logrus.Logger
	userBloomFilter *bloom.BloomFilter
}

// Global variables
var (
	dbService *DatabaseService
	jwtSecret []byte
	logger    *logrus.Logger
)

func main() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	logger.Info("Starting StreamFlow User Service...")

	// Load environment variables
	err := godotenv.Load(".env")
	if err != nil {
		logger.WithError(err).Fatal("Error loading .env file")
	}

	// Initialize JWT secret
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("default-secret-key-change-in-production")
		logger.Warn("Using default JWT secret. Please set JWT_SECRET in production")
	}

	// Connect to MongoDB
	MONGODB_URI := os.Getenv("MONGODB_URI")
	if MONGODB_URI == "" {
		MONGODB_URI = "mongodb://localhost:27017"
	}

	clientOptions := options.Client().ApplyURI(MONGODB_URI)
	clientOptions.SetServerSelectionTimeout(30 * time.Second)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to MongoDB")
	}

	defer client.Disconnect(context.Background())

	err = client.Ping(context.Background(), nil)
	if err != nil {
		logger.WithError(err).Fatal("Failed to ping MongoDB")
	}

	logger.Info("Connected to MongoDB successfully")

	// Initialize database service
	dbService = &DatabaseService{
		usersCollection: client.Database("userService_db").Collection("users"),
		logger:          logger,
		userBloomFilter: bloom.NewWithEstimates(1000000, 0.01), // 1M users, 1% false positive rate
	}

	// Initialize bloom filter with existing usernames
	err = dbService.initializeBloomFilter()
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize bloom filter with existing users")
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})

	// Add CORS middleware for frontend usage
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*", // Common Vite dev server ports
		AllowMethods:     "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// Serve static files from public directory
	app.Static("/", "./public")

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy", "timestamp": time.Now()})
	})

	// Favicon route to prevent 404 errors
	app.Get("/favicon.ico", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	// Auth routes (no middleware) - these should be public
	auth := app.Group("/api/auth")
	auth.Post("/register", registerHandler)
	auth.Post("/login", loginHandler)

	// Protected routes (require authentication)
	protected := app.Group("/api", authMiddleware)
	protected.Get("/users", getUsers)
	protected.Get("/users/:id", getUserByID)
	protected.Patch("/users/:id", updateUsers)
	protected.Delete("/users/:id", deleteUsers)
	protected.Get("/profile", getProfile)

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "3000"
	}

	logger.WithField("port", PORT).Info("Server starting")
	logger.Fatal(app.Listen("0.0.0.0:" + PORT))
}

// DatabaseService methods

// initializeBloomFilter loads existing usernames into bloom filter
func (db *DatabaseService) initializeBloomFilter() error {
	cursor, err := db.usersCollection.Find(context.Background(), bson.M{}, options.Find().SetProjection(bson.M{"username": 1}))
	if err != nil {
		return err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user struct {
			Username string `bson:"username"`
		}
		if err := cursor.Decode(&user); err != nil {
			db.logger.WithError(err).Error("Error decoding user for bloom filter")
			continue
		}
		db.userBloomFilter.AddString(user.Username)
	}
	return nil
}

// checkUsernameExists checks if username might exist using bloom filter first
func (db *DatabaseService) checkUsernameExists(username string) (bool, error) {
	// First check bloom filter
	if !db.userBloomFilter.TestString(username) {
		// Definitely doesn't exist
		return false, nil
	}

	// Might exist, check database
	count, err := db.usersCollection.CountDocuments(context.Background(), bson.M{"username": username})
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// createUser creates a new user with hashed password
func (db *DatabaseService) createUser(userReq *UserRequest) (*User, error) {
	// Check if username already exists
	exists, err := db.checkUsernameExists(userReq.Username)
	if err != nil {
		return nil, fmt.Errorf("error checking username: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists
	count, err := db.usersCollection.CountDocuments(context.Background(), bson.M{"email": userReq.Email})
	if err != nil {
		return nil, fmt.Errorf("error checking email: %w", err)
	}
	if count > 0 {
		return nil, fmt.Errorf("email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userReq.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	// Create user
	user := &User{
		ID:        primitive.NewObjectID(),
		Username:  userReq.Username,
		Email:     userReq.Email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
		LastLogin: time.Time{},
	}

	// Insert user
	_, err = db.usersCollection.InsertOne(context.Background(), user)
	if err != nil {
		return nil, fmt.Errorf("error inserting user: %w", err)
	}

	// Add username to bloom filter
	db.userBloomFilter.AddString(user.Username)

	// Log user creation
	db.logger.WithFields(logrus.Fields{
		"user_id":  user.ID.Hex(),
		"username": user.Username,
	}).Info("User created successfully")

	return user, nil
}

// authenticateUser validates user credentials
func (db *DatabaseService) authenticateUser(loginReq *LoginRequest) (*User, error) {
	var user User
	err := db.usersCollection.FindOne(context.Background(), bson.M{"username": loginReq.Username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("error finding user: %w", err)
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	user.LastLogin = time.Now()
	_, err = db.usersCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{"lastLogin": user.LastLogin}},
	)
	if err != nil {
		db.logger.WithError(err).Error("Failed to update last login")
	}

	db.logger.WithFields(logrus.Fields{
		"user_id":  user.ID.Hex(),
		"username": user.Username,
	}).Info("User authenticated successfully")

	return &user, nil
}

// getUserByID retrieves a user by ID
func (db *DatabaseService) getUserByID(userID string) (*User, error) {
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	var user User
	err = db.usersCollection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error finding user: %w", err)
	}

	return &user, nil
}

// getAllUsers retrieves all users
func (db *DatabaseService) getAllUsers() ([]User, error) {
	var users []User
	cursor, err := db.usersCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, fmt.Errorf("error finding users: %w", err)
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user User
		if err := cursor.Decode(&user); err != nil {
			db.logger.WithError(err).Error("Error decoding user")
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// updateUser updates user information
func (db *DatabaseService) updateUser(userID string, updates map[string]interface{}) error {
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID")
	}

	// Remove sensitive fields that shouldn't be updated directly
	delete(updates, "password")
	delete(updates, "_id")
	delete(updates, "createdAt")

	if len(updates) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	_, err = db.usersCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		bson.M{"$set": updates},
	)
	if err != nil {
		return fmt.Errorf("error updating user: %w", err)
	}

	db.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"updates": updates,
	}).Info("User updated successfully")

	return nil
}

// deleteUser removes a user from the database
func (db *DatabaseService) deleteUser(userID string) error {
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID")
	}

	_, err = db.usersCollection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}

	db.logger.WithField("user_id", userID).Info("User deleted successfully")
	return nil
}

// Utility functions

// generateJWT creates a JWT token for a user
func generateJWT(user *User) (string, error) {
	claims := &Claims{
		UserID:   user.ID.Hex(),
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Middleware

// authMiddleware validates JWT tokens
func authMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		logger.Warn("Missing authorization header")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing authorization token",
		})
	}

	// Extract token from "Bearer <token>" format
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		logger.Warn("Invalid authorization header format")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid authorization header format",
		})
	}

	tokenString := tokenParts[1]

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		logger.WithError(err).Warn("Invalid token")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token",
		})
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Store user info in context for handlers to use
		c.Locals("user_id", claims.UserID)
		c.Locals("username", claims.Username)
		return c.Next()
	}

	logger.Warn("Token validation failed")
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "Invalid token",
	})
}

// customErrorHandler handles errors globally
func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	logger.WithFields(logrus.Fields{
		"error":  err.Error(),
		"path":   c.Path(),
		"method": c.Method(),
		"ip":     c.IP(),
	}).Error("Request error")

	return c.Status(code).JSON(fiber.Map{
		"error":     message,
		"timestamp": time.Now(),
		"path":      c.Path(),
	})
}

// HTTP Handlers

// registerHandler handles user registration
func registerHandler(c *fiber.Ctx) error {
	var userReq UserRequest
	if err := c.BodyParser(&userReq); err != nil {
		logger.WithError(err).Warn("Invalid request body for registration")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate required fields
	if userReq.Username == "" || userReq.Email == "" || userReq.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username, email, and password are required",
		})
	}

	// Validate password length
	if len(userReq.Password) < 6 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password must be at least 6 characters long",
		})
	}

	// Create user
	user, err := dbService.createUser(&userReq)
	if err != nil {
		if strings.Contains(err.Error(), "username already exists") {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Username already exists. Please choose a unique username.",
			})
		}
		if strings.Contains(err.Error(), "email already exists") {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Email already exists",
			})
		}
		logger.WithError(err).Error("Failed to create user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user",
		})
	}

	// Generate JWT token
	token, err := generateJWT(user)
	if err != nil {
		logger.WithError(err).Error("Failed to generate token")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate authentication token",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(LoginResponse{
		Token: token,
		User:  *user,
	})
}

// loginHandler handles user authentication
func loginHandler(c *fiber.Ctx) error {
	var loginReq LoginRequest
	if err := c.BodyParser(&loginReq); err != nil {
		logger.WithError(err).Warn("Invalid request body for login")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate required fields
	if loginReq.Username == "" || loginReq.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username and password are required",
		})
	}

	// Authenticate user
	user, err := dbService.authenticateUser(&loginReq)
	if err != nil {
		if strings.Contains(err.Error(), "invalid credentials") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid username or password",
			})
		}
		logger.WithError(err).Error("Failed to authenticate user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Authentication failed",
		})
	}

	// Generate JWT token
	token, err := generateJWT(user)
	if err != nil {
		logger.WithError(err).Error("Failed to generate token")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate authentication token",
		})
	}

	return c.JSON(LoginResponse{
		Token: token,
		User:  *user,
	})
}

// getUsers handles getting all users (protected)
func getUsers(c *fiber.Ctx) error {
	users, err := dbService.getAllUsers()
	if err != nil {
		logger.WithError(err).Error("Failed to get users")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve users",
		})
	}

	return c.JSON(fiber.Map{
		"users": users,
		"count": len(users),
	})
}

// getUserByID handles getting a specific user (protected)
func getUserByID(c *fiber.Ctx) error {
	userID := c.Params("id")
	user, err := dbService.getUserByID(userID)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		if strings.Contains(err.Error(), "invalid user ID") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid user ID",
			})
		}
		logger.WithError(err).Error("Failed to get user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve user",
		})
	}

	return c.JSON(user)
}

// getProfile handles getting current user's profile (protected)
func getProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	user, err := dbService.getUserByID(userID)
	if err != nil {
		logger.WithError(err).Error("Failed to get user profile")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve profile",
		})
	}

	return c.JSON(user)
}

// updateUsers handles updating user information (protected)
func updateUsers(c *fiber.Ctx) error {
	userID := c.Params("id")
	currentUserID := c.Locals("user_id").(string)

	// Users can only update their own profile (unless admin - not implemented)
	if userID != currentUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You can only update your own profile",
		})
	}

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		logger.WithError(err).Warn("Invalid request body for update")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	err := dbService.updateUser(userID, updates)
	if err != nil {
		if strings.Contains(err.Error(), "no valid fields to update") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No valid fields to update",
			})
		}
		if strings.Contains(err.Error(), "invalid user ID") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid user ID",
			})
		}
		logger.WithError(err).Error("Failed to update user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	return c.JSON(fiber.Map{"message": "User updated successfully"})
}

// deleteUsers handles user deletion (protected)
func deleteUsers(c *fiber.Ctx) error {
	userID := c.Params("id")
	currentUserID := c.Locals("user_id").(string)

	// Users can only delete their own account (unless admin - not implemented)
	if userID != currentUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You can only delete your own account",
		})
	}

	err := dbService.deleteUser(userID)
	if err != nil {
		if strings.Contains(err.Error(), "invalid user ID") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid user ID",
			})
		}
		logger.WithError(err).Error("Failed to delete user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}
