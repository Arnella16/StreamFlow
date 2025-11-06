# Go Elasticsearch Service 🚀

This project is a Go-based microservice for video search, powered by Elasticsearch. It's designed to be run as a containerized application using Docker Compose.
 
This guide covers two methods:
 
1.  **Quick Run:** (Easiest) Pulls a pre-built, public image from Docker Hub.
2.  **Developer Setup:** (Advanced) Builds the Go service from your local source code.
 
 ---
 
 ## 1. Quick Run (Recommended)
 
 This method instantly runs the application using the pre-built public Docker image **`woholo/go-search-service:latest`**. You don't need the Go source code for this.
 
 ### How to Run
 
 1.  Make sure you have **Docker Desktop** installed and running.
 2.  Save the code below into a file named `docker-compose.yml`.
 3.  Open your terminal in the same folder and run:
 
     ```bash
     docker compose up
     ```
 4.  Docker will automatically download (pull) both the `elasticsearch:8.11.1` image and the `woholo/go-search-service:latest` image and start them.
 5.  After the health check passes, your service will be running and accessible at `http://localhost:8080`.
 
 ### `docker-compose.yml` for Quick Run
 
 ```yaml
 services:
   elasticsearch:
     image: elasticsearch:8.11.1
     ports:
       - "9200:9200"
     environment:
       - discovery.type=single-node
       - xpack.security.enabled=false
       - ES_JAVA_OPTS=-Xms1g -Xmx1g
     volumes:
       - esdata:/usr/share/elasticsearch/data
     restart: always
     networks:
       - elastic_net
     healthcheck:
       test: ["CMD", "curl", "-f", "http://localhost:9200"]
       interval: 10s
       timeout: 5s
       retries: 5
       start_period: 60s
   
   go-search-service:
     # This pulls the public image from Docker Hub
     image: woholo/go-search-service:latest
     ports:
       - "8080:8080"
     environment:
       - ELASTICSEARCH_URL=http://elasticsearch:9200
     depends_on:
       elasticsearch:
         condition: service_healthy
     restart: always
     networks:
       - elastic_net
 
 volumes:
   esdata:
 
 networks:
   elastic_net:
 ```
 
 ---
 
 ## 2. Developer Setup (Build From Source)
 
 Use this method if you have cloned the Go source code (`main.go`, `Dockerfile`, etc.) and want to build the image yourself.
 
 ### 1. Build and Run
 
 In your project's root folder (containing the `Dockerfile` and `docker-compose.yml`), run:
 
 ```bash
 docker compose up --build
 ```
 This will build your Go code, start Elasticsearch, wait for it to be healthy, and then start your Go service.
 
 ### 2. `docker-compose.yml` for Building
 
 This file uses `build: .` to build your local `Dockerfile` instead of pulling from the hub.
 
 ```yaml
 services:
   elasticsearch:
     image: elasticsearch:8.11.1
     ports:
       - "9200:9200"
     environment:
       - discovery.type=single-node
       - xpack.security.enabled=false
       - ES_JAVA_OPTS=-Xms1g -Xmx1g
     volumes:
       - esdata:/usr/share/elasticsearch/data
     restart: always
     networks:
       - elastic_net
     healthcheck:
       test: ["CMD", "curl", "-f", "http://localhost:9200"]
       interval: 10s
       timeout: 5s
       retries: 5
       start_period: 60s
   
   go-search-service:
     # This builds your local Dockerfile
     build: .
     ports:
       - "8080:8080"
     environment:
       - ELASTICSEARCH_URL=http://elasticsearch:9200
     depends_on:
       elasticsearch:
         condition: service_healthy
     restart: always
     networks:
       - elastic_net
 
 volumes:
   esdata:
 
 networks:
   elastic_net:
 ```
 
 ---
 
 ## 3. Stopping the Application
 
 To stop and remove all running containers and the network, press **`Ctrl + C`** in the terminal (if it's attached) or run:
 
 ```bash
 docker compose down
 ```
 
 **To delete your Elasticsearch data volume** and start fresh, run:
 
 ```bash
 docker compose down -v
 ```
 
 ---
 
 ## 4. Testing Your Service 🧪
 
 Once your containers are running (using either method), you can use a tool like Postman to test your API at `http://localhost:8080`.
 
 ### 1. Add Data (Bulk Indexing)
 
 * **Request Type:** `POST`
 
 * **URL:** `http://localhost:8080/bulk`
 
 * **Body Type:** In Postman, go to **Body** -> **raw**.
 
 * **Format:** Paste the text below. **Do not** set the format to `JSON`, as the bulk endpoint expects newline-delimited text.
 
 ```json
 { "index" : { "_index" : "videos", "_id" : "vid001" } }
 { "id": "vid001", "title": "Funny Cat Moments", "description": "A hilarious compilation of cat and kitten videos.", "author": "Viral Pets" }
 { "index" : { "_index" : "videos", "_id" : "vid002" } }
 { "id": "vid002", "title": "Training Your Dog: The Basics", "description": "A simple guide for new dog owners.", "author": "Pro Trainer" }
 { "index" : { "_index" : "videos", "_id" : "vid003" } }
 { "id": "vid003", "title": "The Art of Baking Bread", "description": "Learn to bake artisanal bread at home.", "author": "Le Chef" }
 { "index" : { "_index" : "videos", "_id" : "vid004" } }
 { "id": "vid004", "title": "Advanced Go Programming", "description": "Exploring concurrency and channels in Golang.", "author": "Go Gurus" }
 { "index" : { "_index" : "videos", "_id" : "vid005" } }
 { "id": "vid005", "title": "Understanding Your Pet Cat's Behavior", "description": "A deep dive into the psychology of the modern house cat.", "author": "Pet Insights" }
 { "index" : { "_index" : "videos", "_id" : "vid006" } }
 { "id": "vid006", "title": "Baking the Perfect Birthday Cake", "description": "A step-by-step recipe for a delicious layer cake.", "author": "Sweet Treats" }
 ```
 
 ### 2. Search for Data
 
 Now that you have data, you can query your search endpoints.
 
 * **Request Type:** `GET`
 
 * **Example URLs:**
 
   * **Sentence Search:** `http://localhost:8080/sentence-search?q=cook tasty bread or cake`
 
   * **Fuzzy Search (typo):** `http://localhost:8080/fuzzy-search?q=golaang`
 
   * **Prefix/Autocomplete:** `http://localhost:8080/sentence-search?q=cat`
 
 ---
 
 ## 5. Pushing Your Image to the Cloud ☁️
 
 If you built your own image (Method 2) and want to push it to Docker Hub to deploy to a cloud VM:
 
 ### 1. Log In to Docker Hub
 
 ```bash
 docker login
 ```
 
 ### 2. Tag Your Image
 
 Find your local image name (`docker images`) and re-tag it with your Docker Hub username.

 ```bash
 # 1. Find your image name (e.g., go-search-service_go-search-service)
 docker images
 
 # 2. Tag it (replace 'myusername' with your Docker Hub username)
 docker tag go-search-service_go-search-service myusername/go-search-service:v1
 ```
 
 ### 3. Push Your Image
 
 Upload your image to the registry.
 
 ```bash
 docker push myusername/go-search-service:v1
 ```
 
 Your image is now in the cloud, ready to be pulled by any VM or cloud service.
