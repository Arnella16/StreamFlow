package main

import (
	"context"
	"fmt"
	"log" // <-- Import log
	"os"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v4"

	// "github.com/joho/godotenv" // <-- We don't need this
	"github.com/sirupsen/logrus" // You can use this, but 'log' is also fine
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// ... (Your User, UserRequest, LoginRequest, Claims, and DatabaseService structs are all PERFECT) ...
type User struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"username"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"-" bson:"password"` // Hide password in JSON responses
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	LastLogin time.Time          `json:"lastLogin" bson:"lastLogin"`
}
type UserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}
type DatabaseService struct {
	usersCollection *mongo.Collection
	logger          *logrus.Logger
	userBloomFilter *bloom.BloomFilter
}

var (
	dbService *DatabaseService
	jwtSecret []byte
	logger    *logrus.Logger
)

// --- THIS IS THE CORRECTED MAIN FUNCTION ---
func main() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	logger.Info("Starting StreamFlow User Service...")

	// Load environment variables (REMOVED .env loading)
	// err := godotenv.Load(".env")

	// Initialize JWT secret from environment
	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		jwtSecretStr = "default-secret-key-change-in-production"
		logger.Warn("Using default JWT secret. Please set JWT_SECRET in production")
	}
	jwtSecret = []byte(jwtSecretStr)

	// Connect to MongoDB
	MONGODB_URI := os.Getenv("MONGODB_URI")
	if MONGODB_URI == "" {
		// Default to the Docker service name, not localhost
		MONGODB_URI = "mongodb://mongodb:27017"
		logger.Warn("MONGODB_URI not set, defaulting to mongodb://mongodb:27017")
	}

	clientOptions := options.Client().ApplyURI(MONGODB_URI)
	clientOptions.SetServerSelectionTimeout(30 * time.Second)

	// --- Added retry logic for database connection ---
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create MongoDB client")
	}

	for i := 0; i < 10; i++ {
		err = client.Ping(context.Background(), nil)
		if err == nil {
			break // Success!
		}
		logger.Printf("MongoDB not ready yet (attempt %d/10), retrying in 3s...", i+1)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		logger.WithError(err).Fatal("Failed to ping MongoDB after retries")
	}
	// --- End of retry logic ---

	logger.Info("Connected to MongoDB successfully")

	// Initialize database service
	dbService = &DatabaseService{
		usersCollection: client.Database("userService_db").Collection("users"),
		logger:          logger,
		userBloomFilter: bloom.NewWithEstimates(1000000, 0.01), // 1M users, 1% false positive rate
	}

	// Initialize bloom filter
	err = dbService.initializeBloomFilter()
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize bloom filter")
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})

	// Add CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://98.70.25.253,http://98.70.25.253:3000,http://localhost:3000,http://98.70.25.253:5173,http://localhost:5173,http://98.70.25.253:8081,http://localhost:8081",
		AllowMethods:     "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// ... (Rest of your routes and functions are PERFECT, no changes needed) ...
	// ... (app.Static, /health, /favicon.ico, auth.Post, protected.Get, etc.) ...

	// Auth routes
	auth := app.Group("/api/auth")
	auth.Post("/register", registerHandler)
	auth.Post("/login", loginHandler)

	// Protected routes
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
	log.Fatal(app.Listen("0.0.0.0:" + PORT))
}

// ... (All your other functions: initializeBloomFilter, createUser, authMiddleware, etc. are all fine) ...
// ... (Make sure to paste them all here) ...

// --- PASTE ALL YOUR OTHER FUNCTIONS HERE ---
// (DatabaseService methods, Utility functions, Middleware, HTTP Handlers)

// DatabaseService methods
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
func (db *DatabaseService) checkUsernameExists(username string) (bool, error) {
	if !db.userBloomFilter.TestString(username) {
		return false, nil
	}
	count, err := db.usersCollection.CountDocuments(context.Background(), bson.M{"username": username})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
func (db *DatabaseService) createUser(userReq *UserRequest) (*User, error) {
	exists, err := db.checkUsernameExists(userReq.Username)
	if err != nil {
		return nil, fmt.Errorf("error checking username: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("username already exists")
	}
	count, err := db.usersCollection.CountDocuments(context.Background(), bson.M{"email": userReq.Email})
	if err != nil {
		return nil, fmt.Errorf("error checking email: %w", err)
	}
	if count > 0 {
		return nil, fmt.Errorf("email already exists")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userReq.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}
	user := &User{
		ID:        primitive.NewObjectID(),
		Username:  userReq.Username,
		Email:     userReq.Email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
		LastLogin: time.Time{},
	}
	_, err = db.usersCollection.InsertOne(context.Background(), user)
	if err != nil {
		return nil, fmt.Errorf("error inserting user: %w", err)
	}
	db.userBloomFilter.AddString(user.Username)
	db.logger.WithFields(logrus.Fields{
		"user_id":  user.ID.Hex(),
		"username": user.Username,
	}).Info("User created successfully")
	return user, nil
}
func (db *DatabaseService) authenticateUser(loginReq *LoginRequest) (*User, error) {
	var user User
	err := db.usersCollection.FindOne(context.Background(), bson.M{"username": loginReq.Username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("error finding user: %w", err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
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
func (db *DatabaseService) updateUser(userID string, updates map[string]interface{}) error {
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID")
	}
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
func authMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		logger.Warn("Missing authorization header")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing authorization token",
		})
	}
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		logger.Warn("Invalid authorization header format")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid authorization header format",
		})
	}
	tokenString := tokenParts[1]
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
		c.Locals("user_id", claims.UserID)
		c.Locals("username", claims.Username)
		return c.Next()
	}
	logger.Warn("Token validation failed")
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "Invalid token",
	})
}
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
func registerHandler(c *fiber.Ctx) error {
	var userReq UserRequest
	if err := c.BodyParser(&userReq); err != nil {
		logger.WithError(err).Warn("Invalid request body for registration")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}
	if userReq.Username == "" || userReq.Email == "" || userReq.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username, email, and password are required",
		})
	}
	if len(userReq.Password) < 6 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password must be at least 6 characters long",
		})
	}
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
func loginHandler(c *fiber.Ctx) error {
	var loginReq LoginRequest
	if err := c.BodyParser(&loginReq); err != nil {
		logger.WithError(err).Warn("Invalid request body for login")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}
	if loginReq.Username == "" || loginReq.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username and password are required",
		})
	}
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
func updateUsers(c *fiber.Ctx) error {
	userID := c.Params("id")
	currentUserID := c.Locals("user_id").(string)
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
func deleteUsers(c *fiber.Ctx) error {
	userID := c.Params("id")
	currentUserID := c.Locals("user_id").(string)
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
