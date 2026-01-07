package main

import (
	"context" // <-- Added for fmt.Sprintf
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"go.mongodb.org/mongo-driver/bson"

	// "github.com/joho/godotenv" // <-- REMOVED
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Define struct for video social info
type VideoSocial struct {
	ID          string    `json:"id" bson:"_id"`
	Title       string    `json:"title" bson:"title"`
	Description string    `json:"description" bson:"description"`
	Author      string    `json:"author" bson:"author"`
	Thumbnail   string    `json:"thumbnail" bson:"thumbnail"`
	Path        string    `json:"path" bson:"path"`
	Duration    float64   `json:"duration" bson:"duration"`
	Views       int       `json:"views" bson:"views"`
	Likes       int       `json:"likes" bson:"likes"`
	Comments    []string  `json:"comments" bson:"comments"`
	CreatedAt   time.Time `json:"createdAt" bson:"createdAt"`
}

var collection *mongo.Collection

func main() {
	// Load environment variables from .env file
	// err := godotenv.Load() // <-- REMOVED

	// Connect to MongoDB
	MONGODB_URI := os.Getenv("MONGODB_URI")
	if MONGODB_URI == "" {
		// Default to the Docker service name
		MONGODB_URI = "mongodb://mongodb:27017"
	}

	clientOptions := options.Client().ApplyURI(MONGODB_URI)
	clientOptions.SetServerSelectionTimeout(30 * time.Second)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("❌ Failed to connect to MongoDB: %v", err)
	}
	defer client.Disconnect(context.Background())

	// --- Added retry logic for connection ---
	for i := 0; i < 10; i++ {
		err = client.Ping(context.Background(), nil)
		if err == nil {
			break // Success!
		}
		log.Printf("MongoDB not ready yet (attempt %d/10), retrying in 3s...", i+1)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatalf("❌ Failed to ping MongoDB after retries: %v", err)
	}
	// --- End of retry logic ---

	log.Println("✅ Connected to MongoDB successfully")

	// Initialize collection
	collection = client.Database("socials_db").Collection("videos")

	// Fiber app setup
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://98.70.25.253,http://98.70.25.253:3000,http://localhost:3000,http://98.70.25.253:5173,http://localhost:5173,http://98.70.25.253:8081",
		AllowMethods:     "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	ctx := context.Background()

	// ROUTES -------------------------
	// (All your handlers: /init, /videos/:id/like, etc. are correct)

	// Create social record when video is uploaded
	app.Post("/init", func(c *fiber.Ctx) error {
		var payload struct {
			ID          string  `json:"id"`
			Title       string  `json:"title"`
			Description string  `json:"description"`
			Author      string  `json:"author"`
			Thumbnail   string  `json:"thumbnail"`
			Path        string  `json:"path"`
			Duration    float64 `json:"duration"`
		}
		if err := c.BodyParser(&payload); err != nil {
			return c.Status(400).SendString("Invalid payload")
		}

		doc := bson.M{
			"_id":         payload.ID,
			"title":       payload.Title,
			"description": payload.Description,
			"author":      payload.Author,
			"thumbnail":   payload.Thumbnail,
			"path":        payload.Path,
			"duration":    payload.Duration,
			"views":       0,
			"likes":       0,
			"comments":    []string{},
			"createdAt":   time.Now(),
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			// Handle case where video is re-uploaded (duplicate _id)
			if mongo.IsDuplicateKeyError(err) {
				log.Println("Info: Video ID already exists, skipping init.")
				return c.JSON(fiber.Map{"status": "ok (already exists)", "video": payload.ID})
			}
			return c.Status(500).SendString("DB insert error")
		}

		return c.JSON(fiber.Map{"status": "ok", "video": payload.ID})
	})

	// Like a video by ID
	app.Post("/videos/:id/like", func(c *fiber.Ctx) error {
		id := c.Params("id")

		_, err := collection.UpdateOne(ctx,
			bson.M{"_id": id},
			bson.M{"$inc": bson.M{"likes": 1}},
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"message": "Like added"})
	})

	// Add a comment
	app.Post("/videos/:id/comment", func(c *fiber.Ctx) error {
		id := c.Params("id")
		var body struct {
			Text string `json:"text"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		_, err := collection.UpdateOne(ctx,
			bson.M{"_id": id},
			bson.M{"$push": bson.M{"comments": body.Text}},
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"message": "Comment added"})
	})

	// Increment view count
	app.Post("/videos/:id/view", func(c *fiber.Ctx) error {
		id := c.Params("id")

		_, err := collection.UpdateOne(ctx,
			bson.M{"_id": id},
			bson.M{"$inc": bson.M{"views": 1}},
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"message": "View count incremented"})
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
