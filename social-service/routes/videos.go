package routes

import "github.com/gofiber/fiber/v2"

// Video represents a simple video structure
type Video struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnailUrl"`
	LikesCount   int    `json:"likesCount"`
	ViewsCount   int    `json:"viewsCount"`
}

// RegisterVideoRoutes adds video-related routes to the app
func RegisterVideoRoutes(app *fiber.App) {
	app.Get("/api/videos/my", func(c *fiber.Ctx) error {
		// TODO: Replace with actual user ID and DB query
		videos := []Video{
			{
				ID:           "1",
				Title:        "My First Video",
				ThumbnailURL: "https://via.placeholder.com/150",
				LikesCount:   10,
				ViewsCount:   100,
			},
			{
				ID:           "2",
				Title:        "Another Video",
				ThumbnailURL: "https://via.placeholder.com/150",
				LikesCount:   5,
				ViewsCount:   50,
			},
		}
		return c.JSON(videos)
	})
}
