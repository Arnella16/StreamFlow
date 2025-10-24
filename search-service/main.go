package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

// Video represents the structure of our video data.
type Video struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Author      string `json:"author"`
}

// Global Elasticsearch client
var es *elasticsearch.Client

const indexName = "videos" // Name of our Elasticsearch index

func main() {
	var err error
	es, err = elasticsearch.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error creating the client: %s", err)
	}

	res, err := es.Info()
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	defer res.Body.Close()
	log.Println(res)

	// Define our HTTP endpoints
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/exact-word-search", searchHandler) // Renamed
	http.HandleFunc("/fuzzy-search", fuzzySearchHandler) // <-- ADDED THIS NEW ENDPOINT
	http.HandleFunc("/bulk", bulkIndexHandler)
	http.HandleFunc("/create-indexes", createIndexesHandler)

	// Start the web server
	fmt.Println("Server is listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// NEW STRUCT for parsing the JSON request for creating indexes
type CreateIndexesRequest struct {
	Indexes []string `json:"indexes"`
}

// Function to handle creating multiple indexes
func createIndexesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqPayload CreateIndexesRequest
	if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	var results = make(map[string]string)
	var hadErrors bool

	for _, indexName := range reqPayload.Indexes {
		res, err := es.Indices.Create(indexName)
		if err != nil {
			results[indexName] = fmt.Sprintf("Error sending request: %s", err)
			hadErrors = true
			continue
		}
		defer res.Body.Close()

		if res.IsError() {
			results[indexName] = fmt.Sprintf("Error from Elasticsearch: %s", res.String())
			hadErrors = true
		} else {
			results[indexName] = "Successfully created"
		}
	}

	responseBody, _ := json.Marshal(results)
	w.Header().Set("Content-Type", "application/json")
	if hadErrors {
		w.WriteHeader(http.StatusMultiStatus)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Write(responseBody)
}

// Function to handle bulk indexing
func bulkIndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	res, err := es.Bulk(bytes.NewReader(body), es.Bulk.WithIndex(indexName))
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting response: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		http.Error(w, res.String(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Bulk indexing successful!")
}

// indexHandler handles adding a single new video to the index.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var video Video
	err := json.NewDecoder(r.Body).Decode(&video)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	videoJSON, err := json.Marshal(video)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req := esapi.IndexRequest{
		Index:      indexName,
		DocumentID: video.ID,
		Body:       bytes.NewReader(videoJSON),
		Refresh:    "true",
	}

	res, err := req.Do(context.Background(), es)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting response: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("[%s] Error indexing document ID=%s", res.Status(), video.ID)
		http.Error(w, res.String(), http.StatusInternalServerError)
	} else {
		var r map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			log.Printf("Error parsing the response body: %s", err)
		} else {
			log.Printf("[%s] %s; version=%d", res.Status(), r["result"], int(r["_version"].(float64)))
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Video indexed successfully with ID: %s", video.ID)
	}
}

// Main search handler (renamed to exact_word_search)
func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	author := r.URL.Query().Get("author")

	if query == "" {
		http.Error(w, "Query parameter 'q' is missing", http.StatusBadRequest)
		return
	}

	var queryBody map[string]interface{}
	mustClauses := []map[string]interface{}{
		{
			"multi_match": map[string]interface{}{
				"query":  query,
				"fields": []string{"title", "description"},
			},
		},
	}

	if author != "" {
		filterClauses := []map[string]interface{}{
			{
				"term": map[string]interface{}{
					"author.keyword": author,
				},
			},
		}
		queryBody = map[string]interface{}{
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must":   mustClauses,
					"filter": filterClauses,
				},
			},
		}
	} else {
		queryBody = map[string]interface{}{
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": mustClauses,
				},
			},
		}
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(queryBody); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding query: %s", err), http.StatusInternalServerError)
		return
	}

	// Use the common search execution function
	executeSearch(w, &buf)
}

// NEW FUNCTION to handle fuzzy search
func fuzzySearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is missing", http.StatusBadRequest)
		return
	}

	// Build the fuzzy query
	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"fuzzy": map[string]interface{}{
				"title": map[string]interface{}{
					"value":     query,
					"fuzziness": "AUTO", // Allows for automatic edit distance
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(queryBody); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding query: %s", err), http.StatusInternalServerError)
		return
	}

	// Re-use the search logic by calling the common search execution function
	executeSearch(w, &buf)
}

// NEW COMMON FUNCTION to execute a search and write the response
func executeSearch(w http.ResponseWriter, queryBody io.Reader) {
	res, err := es.Search(
		es.Search.WithContext(context.Background()),
		es.Search.WithIndex(indexName),
		es.Search.WithBody(queryBody),
		es.Search.WithTrackTotalHits(true),
		es.Search.WithPretty(),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting response: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			http.Error(w, fmt.Sprintf("Error parsing the response body: %s", err), http.StatusInternalServerError)
		} else {
			log.Printf("[%s] %s: %s", res.Status(), e["error"].(map[string]interface{})["type"], e["error"].(map[string]interface{})["reason"])
			http.Error(w, "Search failed", http.StatusInternalServerError)
		}
		return
	}

	var searchResult map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&searchResult); err != nil {
		http.Error(w, fmt.Sprintf("Error parsing the response body: %s", err), http.StatusInternalServerError)
		return
	}

	hits := searchResult["hits"].(map[string]interface{})["hits"].([]interface{})
	var videos []Video
	for _, hit := range hits {
		source := hit.(map[string]interface{})["_source"]
		videoBytes, _ := json.Marshal(source)
		var video Video
		json.Unmarshal(videoBytes, &video)
		videos = append(videos, video)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(videos)
}
