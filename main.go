package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserService struct {
	ID        primitive.ObjectID `json:"_id" 		bson:"_id,omitempty"`
	Username  string             `json:"username" 	bson:"username"`
	Email     string             `json:"email" 		bson:"email"`
	Password  string             `json:"password" 	bson:"password"`
	CreatedAt time.Time          `json:"createdAt" 	bson:"createdAt"`
	LastLogin time.Time          `json:"lastLogin" 	bson:"lastLogin"`
}

var collection *mongo.Collection

func main() {
	fmt.Println("Hello, World!")

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	MONGODB_URI := os.Getenv("MONGODB_URI")
	clientOptions := options.Client().ApplyURI(MONGODB_URI)
	clientOptions.SetServerSelectionTimeout(30 * time.Second)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	defer client.Disconnect(context.Background())

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	fmt.Println("Connected to MongoDB!")

	collection = client.Database("userService_db").Collection("users")

	app := fiber.New()

	app.Get("/api/users", getUsers)
	app.Post("/api/users", createUsers)
	app.Patch("/api/users/:id", updateUsers)
	app.Delete("/api/users/:id", deleteUsers)

	PORT := os.Getenv("PORT")

	if PORT == "" {
		PORT = "3000"
	}

	log.Fatal(app.Listen("0.0.0.0:" + PORT))
}

func getUsers(c *fiber.Ctx) error {
	var users []UserService

	cursor, err := collection.Find(context.Background(), bson.M{})

	if err != nil {
		return err
	}

	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user UserService
		if err := cursor.Decode(&user); err != nil {
			return err
		}
		users = append(users, user)
	}

	return c.JSON(users)
}

func createUsers(c *fiber.Ctx) error {
	user := new(UserService)

	err := c.BodyParser(user)
	if err != nil {
		return err
	}

	if user.Username == "" || user.Email == "" || user.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username, Email, and Password are required fields",
		})
	}

	user.ID = primitive.NewObjectID()

	insertRes, err := collection.InsertOne(context.Background(), user)

	if err != nil {
		return err
	}

	user.ID = insertRes.InsertedID.(primitive.ObjectID)
	return c.Status(201).JSON(user)

}

func updateUsers(c *fiber.Ctx) error {
	id := c.Params("id")
	objectID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	filter := bson.M{"_id": objectID}
	update := bson.M{"$set": bson.M{"username": "TejaSri"}}

	_, err = collection.UpdateOne(context.Background(), filter, update)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	return c.Status(200).JSON(fiber.Map{"success": true})
}

func deleteUsers(c *fiber.Ctx) error {
	id := c.Params("id")
	objectID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	filter := bson.M{"_id": objectID}
	_, err = collection.DeleteOne(context.Background(), filter)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	return c.Status(200).JSON(fiber.Map{"success": true})
}
