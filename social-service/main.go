package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Define struct for video social info
type VideoSocial struct {
	ID        string   `json:"id" bson:"_id"`
	Likes     int      `json:"likes" bson:"likes"`
	Comments  []string `json:"comments" bson:"comments"`
	CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
}

var collection *mongo.Collection

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("❌ Failed to load .env file: %v", err)
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
		log.Fatalf("❌ Failed to connect to MongoDB: %v", err)
	}
	defer client.Disconnect(context.Background())

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("❌ Failed to ping MongoDB: %v", err)
	}

	log.Println("✅ Connected to MongoDB successfully")

	// Initialize collection
	collection = client.Database("socials_db").Collection("videos")

	// Fiber app setup
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
		AllowMethods:     "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	ctx := context.Background()

	// ROUTES -------------------------

	// Create social record when video is uploaded
	app.Post("/init", func(c *fiber.Ctx) error {
		var payload struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Thumbnail string `json:"thumbnail"`
			Path      string `json:"path"`
		}
		if err := c.BodyParser(&payload); err != nil {
			return c.Status(400).SendString("Invalid payload")
		}

		doc := bson.M{
			"_id":       payload.ID,
			"title":     payload.Title,
			"thumbnail": payload.Thumbnail,
			"path":      payload.Path,
			"likes":     0,
			"comments":  []string{},
			"createdAt": time.Now(),
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			return c.Status(500).SendString("DB insert error")
		}

		return c.JSON(fiber.Map{"status": "ok", "video": payload.ID})
	})

	app.Post("/videos/:title/like", func(c *fiber.Ctx) error {
		title := c.Params("title")
		ctx := context.Background()

		_, err := collection.UpdateOne(ctx, bson.M{"title": title}, bson.M{"$inc": bson.M{"likes": 1}})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"message": "Like added"})
	})

	app.Post("/videos/:title/comment", func(c *fiber.Ctx) error {
		title := c.Params("title")
		var body struct {
			Text string `json:"text"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		ctx := context.Background()
		_, err := collection.UpdateOne(ctx,
			bson.M{"title": title},
			bson.M{"$push": bson.M{"comments": body.Text}},
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"message": "Comment added"})
	})


	// Get social info for a video
	app.Get("/video/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
		var video VideoSocial
		err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&video)
		if err != nil {
			return c.Status(404).SendString("Video not found")
		}
		return c.JSON(video)
	})

	// -------------------------------

	// Fetch all videos
	app.Get("/videos", func(c *fiber.Ctx) error {
		ctx := context.Background()
		cursor, err := collection.Find(ctx, bson.M{})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		defer cursor.Close(ctx)

		var videos []bson.M
		if err := cursor.All(ctx, &videos); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(videos)
	})


	log.Println("🚀 Social service running on port 3002")
	app.Listen(":3002")
}
