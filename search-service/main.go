package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
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
	es, err = elasticsearch.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error creating client: %s", err)
	}

	res, err := es.Info()
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	defer res.Body.Close()
	log.Println(res)

	http.HandleFunc("/create-indexes", createIndexesHandler)
	http.HandleFunc("/create-index-with-mapping", createIndexWithMappingHandler)
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/bulk", bulkIndexHandler)
	http.HandleFunc("/exact-word-search", searchHandler)
	http.HandleFunc("/fuzzy-search", fuzzySearchHandler)
	http.HandleFunc("/sentence-search", sentenceSearchHandler)

	fmt.Println("Server is listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// --- Create Index with mapping (better text analysis) ---
func createIndexWithMappingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

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
	      "title": {
	        "type": "text",
	        "analyzer": "english_text"
	      },
	      "description": {
	        "type": "text",
	        "analyzer": "english_text"
	      },
	      "author": {
	        "type": "keyword"
	      }
	    }
	  }
	}`

	// Delete index if exists (for re-run safety)
	es.Indices.Delete([]string{indexName})
	res, err := es.Indices.Create(indexName, es.Indices.Create.WithBody(strings.NewReader(mapping)))
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating index: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Index '%s' created with custom mapping.", indexName)
}

// --- Create multiple indexes handler (unchanged) ---
type CreateIndexesRequest struct {
	Indexes []string `json:"indexes"`
}

func createIndexesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var reqPayload CreateIndexesRequest
	if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	results := make(map[string]string)
	for _, idx := range reqPayload.Indexes {
		res, err := es.Indices.Create(idx)
		if err != nil {
			results[idx] = fmt.Sprintf("Error sending request: %s", err)
			continue
		}
		defer res.Body.Close()
		if res.IsError() {
			results[idx] = fmt.Sprintf("Error: %s", res.String())
		} else {
			results[idx] = "Created"
		}
	}
	resp, _ := json.Marshal(results)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// --- Bulk indexing (modified for analyzer index) ---
func bulkIndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	res, err := es.Bulk(bytes.NewReader(body), es.Bulk.WithIndex(indexName))
	if err != nil {
		http.Error(w, fmt.Sprintf("Error bulk indexing: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	if res.IsError() {
		http.Error(w, res.String(), http.StatusInternalServerError)
		return
	}
	es.Indices.Refresh(es.Indices.Refresh.WithIndex(indexName))
	fmt.Fprintln(w, "Bulk indexing done.")
}

// --- Single Index Handler ---
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var video Video
	if err := json.NewDecoder(r.Body).Decode(&video); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
		http.Error(w, fmt.Sprintf("Error indexing: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		http.Error(w, res.String(), http.StatusInternalServerError)
	} else {
		fmt.Fprintf(w, "Video indexed with ID %s\n", video.ID)
	}
}

// --- Sentence search (new full-text handler) ---
func sentenceSearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Missing ?q=", http.StatusBadRequest)
		return
	}

	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":     query,
				"fields":    []string{"title", "description"},
				"type":      "best_fields",
				"fuzziness": "AUTO",
				"operator":  "or",
			},
		},
	}

	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(queryBody)
	executeSearch(w, &buf)
}

// --- Exact word search handler (unchanged) ---
func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Missing ?q=", http.StatusBadRequest)
		return
	}

	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"match_phrase": map[string]interface{}{
				"description": query,
			},
		},
	}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(queryBody)
	executeSearch(w, &buf)
}

// --- Fuzzy Search Handler (same) ---
func fuzzySearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Missing ?q=", http.StatusBadRequest)
		return
	}

	queryBody := map[string]interface{}{
		"query": map[string]interface{}{
			"fuzzy": map[string]interface{}{
				"title": map[string]interface{}{
					"value":     query,
					"fuzziness": "AUTO",
				},
			},
		},
	}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(queryBody)
	executeSearch(w, &buf)
}

// --- Common search executor ---
func executeSearch(w http.ResponseWriter, queryBody io.Reader) {
	res, err := es.Search(
		es.Search.WithContext(context.Background()),
		es.Search.WithIndex(indexName),
		es.Search.WithBody(queryBody),
		es.Search.WithTrackTotalHits(true),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Search error: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		http.Error(w, res.String(), http.StatusInternalServerError)
		return
	}

	var r map[string]interface{}
	json.NewDecoder(res.Body).Decode(&r)
	hits := r["hits"].(map[string]interface{})["hits"].([]interface{})
	var videos []Video
	for _, h := range hits {
		src := h.(map[string]interface{})["_source"]
		data, _ := json.Marshal(src)
		var v Video
		json.Unmarshal(data, &v)
		videos = append(videos, v)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(videos)
}
