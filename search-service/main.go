package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

type Video struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Author      string `json:"author"`
}

var es *elasticsearch.Client

const indexName = "videos"

func main() {
	var err error

	// ✅ Get the URL from the environment variable
	esURL := os.Getenv("ELASTICSEARCH_URL")
	if esURL == "" {
		// Fallback to localhost if no variable is set
		esURL = "http://localhost:9200"
		log.Printf("ELASTICSEARCH_URL not set, defaulting to %s", esURL)
	}

	cfg := elasticsearch.Config{
		Addresses: []string{
			esURL,
		},
	}

	es, err = elasticsearch.NewClient(cfg)

	if err != nil {
		log.Fatalf("Error creating ES client: %s", err)
	}

	// ✅ Fiber app
	app := fiber.New()

	// ✅ FIX CORS ERRORS HERE
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://127.0.0.1:8081, http://localhost:5173",
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowMethods: "GET, POST, OPTIONS",
	}))

	// ✅ ROUTES
	app.Post("/create-indexes", createIndexesHandler)
	app.Post("/create-index-with-mapping", createIndexWithMappingHandler)
	app.Post("/index", indexHandler)
	app.Post("/bulk", bulkIndexHandler)
	app.Get("/exact-word-search", searchHandler)
	app.Get("/fuzzy-search", fuzzySearchHandler)
	app.Get("/sentence-search", sentenceSearchHandler)

	fmt.Println("Fiber server listening on 8080...")
	log.Fatal(app.Listen(":8080"))
}

func createIndexWithMappingHandler(c *fiber.Ctx) error {
	mapping := `{
	  "settings": {
	    "analysis": {
	      "analyzer": {
	        "english_text": {
	          "type": "standard",
	          "stopwords": "_english_"
	        }
	      }
	    }
	  },
	  "mappings": {
	    "properties": {
	      "title": { "type": "text", "analyzer": "english_text" },
	      "description": { "type": "text", "analyzer": "english_text" },
	      "author": { "type": "keyword" }
	    }
	  }
	}`

	// delete old index if exists
	es.Indices.Delete([]string{indexName})

	res, err := es.Indices.Create(indexName, es.Indices.Create.WithBody(strings.NewReader(mapping)))
	if err != nil {
		return c.Status(500).SendString("Error creating index: " + err.Error())
	}
	defer res.Body.Close()

	return c.SendString("Index created with mapping.")
}

type CreateIndexesRequest struct {
	Indexes []string `json:"indexes"`
}

func createIndexesHandler(c *fiber.Ctx) error {
	var reqPayload CreateIndexesRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid JSON"})
	}

	results := make(map[string]string)

	for _, idx := range reqPayload.Indexes {
		res, err := es.Indices.Create(idx)
		if err != nil {
			results[idx] = "Error: " + err.Error()
			continue
		}
		defer res.Body.Close()

		if res.IsError() {
			results[idx] = res.String()
		} else {
			results[idx] = "Created"
		}
	}

	return c.JSON(results)
}

func bulkIndexHandler(c *fiber.Ctx) error {
	body := c.Body()

	res, err := es.Bulk(bytes.NewReader(body), es.Bulk.WithIndex(indexName))
	if err != nil {
		return c.Status(500).SendString("Bulk error: " + err.Error())
	}
	defer res.Body.Close()

	es.Indices.Refresh(es.Indices.Refresh.WithIndex(indexName))

	return c.SendString("Bulk indexing done.")
}

func indexHandler(c *fiber.Ctx) error {
	var video Video
	if err := c.BodyParser(&video); err != nil {
		return c.Status(400).SendString("Invalid JSON")
	}

	videoJSON, _ := json.Marshal(video)

	req := esapi.IndexRequest{
		Index:      indexName,
		DocumentID: video.ID,
		Body:       bytes.NewReader(videoJSON),
		Refresh:    "true",
	}

	res, err := req.Do(context.Background(), es)
	if err != nil {
		return c.Status(500).SendString("Index error: " + err.Error())
	}
	defer res.Body.Close()

	return c.SendString("Indexed video: " + video.ID)
}

func sentenceSearchHandler(c *fiber.Ctx) error {
	query := c.Query("q")
	if query == "" {
		return c.Status(400).SendString("Missing q=")
	}

	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []interface{}{
					// ✅ Prefix search for autocomplete
					map[string]interface{}{
						"prefix": map[string]interface{}{
							"title": query,
						},
					},
					map[string]interface{}{
						"prefix": map[string]interface{}{
							"description": query,
						},
					},

					// ✅ Fuzzy multi-field search (your original logic)
					map[string]interface{}{
						"multi_match": map[string]interface{}{
							"query":     query,
							"fields":    []string{"title", "description"},
							"type":      "best_fields",
							"fuzziness": "AUTO",
							"operator":  "or",
						},
					},
				},
			},
		},
	}

	return executeSearch(c, queryBody)
}

func searchHandler(c *fiber.Ctx) error {
	query := c.Query("q")
	if query == "" {
		return c.Status(400).SendString("Missing q=")
	}

	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"match_phrase": map[string]interface{}{
				"description": query,
			},
		},
	}

	return executeSearch(c, queryBody)
}

func fuzzySearchHandler(c *fiber.Ctx) error {
	query := c.Query("q")
	if query == "" {
		return c.Status(400).SendString("Missing q=")
	}

	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":     query,
				"fields":    []string{"title^3", "description"},
				"fuzziness": "AUTO",
			},
		},
	}

	return executeSearch(c, queryBody)
}

func executeSearch(c *fiber.Ctx, queryBody interface{}) error {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(queryBody)

	res, err := es.Search(
		es.Search.WithIndex(indexName),
		es.Search.WithBody(&buf),
		es.Search.WithTrackTotalHits(true),
	)
	if err != nil {
		return c.Status(500).SendString("Search error: " + err.Error())
	}
	defer res.Body.Close()

	var r map[string]interface{}
	json.NewDecoder(res.Body).Decode(&r)

	hits := r["hits"].(map[string]interface{})["hits"].([]interface{})

	var videos []Video

	for _, h := range hits {
		src := h.(map[string]interface{})["_source"]
		b, _ := json.Marshal(src)

		var v Video
		json.Unmarshal(b, &v)
		videos = append(videos, v)
	}

	return c.JSON(videos)
}
