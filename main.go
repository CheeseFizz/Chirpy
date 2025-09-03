package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/CheeseFizz/Chirpy/internal/database"
)

// apiConfig
// server metrics and handlers related to config and metrics
type apiConfig struct {
	fileserverHits atomic.Int32
	Queries        *database.Queries
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})

	return handler
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	msg := fmt.Sprintf(
		`<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
</html>`, cfg.fileserverHits.Load())
	data := []byte(msg)

	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("PLATFORM") != "dev" {
		w.WriteHeader(403)
		return
	}

	cfg.fileserverHits.Store(0)

	msg := "System data reset"
	err := cfg.Queries.ResetUsers(r.Context())
	if err != nil {
		log.Println(err)
		msg = "Something went wrong."
	}

	data := []byte(msg)

	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) usersHandler(w http.ResponseWriter, r *http.Request) {
	type acceptFormat struct {
		Email string `json:"email"`
	}

	type Response struct {
		Error      string    `json:"error,omitempty"`
		Id         uuid.UUID `json:"id,omitempty"`
		Created_at time.Time `json:"created_at,omitempty"`
		Updated_at time.Time `json:"updated_at,omitempty"`
		Email      string    `json:"email,omitempty"`
	}

	req := &acceptFormat{}
	response := &Response{}

	w.Header().Set("Content-Type", "application/json")

	err := parseRequestJson(r, req)
	if err != nil {
		response.Error = "Something went wrong"
		w.WriteHeader(400)
	} else {
		user, err := cfg.Queries.CreateUser(r.Context(), req.Email)
		if err != nil {
			response.Error = "Something went wrong"
			w.WriteHeader(400)
		} else {
			response.Email = user.Email
			response.Id = user.ID
			response.Created_at = user.CreatedAt
			response.Created_at = user.UpdatedAt
		}
	}

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		response.Error = "Something went wrong"
	}

	w.WriteHeader(201)
	w.Write(dat)

}

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, r *http.Request) {
	type acceptFormat struct {
		Body    string    `json:"body"`
		User_id uuid.UUID `json:"user_id"`
	}

	naughty := []string{"kerfuffle", "sharbert", "fornax"}

	// type Response struct {
	// 	Error string `json:"error,omitempty"`
	// 	Valid *bool  `json:"valid,omitempty"`
	// }
	type Response struct {
		Error      string    `json:"error,omitempty"`
		Id         uuid.UUID `json:"id,omitempty"`
		Created_at time.Time `json:"created_at,omitempty"`
		Updated_at time.Time `json:"updated_at,omitempty"`
		Body       string    `json:"body,omitempty"`
		User_id    uuid.UUID `json:"user_id,omitempty"`
	}

	var cleaned_body string

	req := &acceptFormat{}
	response := &Response{}

	w.Header().Set("Content-Type", "application/json")

	err := parseRequestJson(r, req)
	if err != nil {
		response.Error = "Something went wrong"
		w.WriteHeader(400)
	} else {
		if len(req.Body) > 140 {
			response.Error = "Chirp is too long"
			w.WriteHeader(400)
		} else {
			cleaned_body = req.Body
			for _, word := range naughty {
				rx := fmt.Sprintf(`(?i)%s`, word)
				re := regexp.MustCompile(rx)
				cleaned_body = re.ReplaceAllString(cleaned_body, "****")
			}

			chirpParams := database.CreateChripParams{
				Body:   cleaned_body,
				UserID: req.User_id,
			}
			chirp, err := cfg.Queries.CreateChrip(r.Context(), chirpParams)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			response.User_id = chirp.UserID
			response.Body = chirp.Body
			response.Created_at = chirp.CreatedAt
			response.Updated_at = chirp.UpdatedAt
			response.Id = chirp.ID
		}
	}

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}

	w.WriteHeader(201)
	w.Write(dat)
}

// Helper functions
func parseRequestJson[T any](r *http.Request, typestruct *T) error {
	// Mutate typestruct with parsed data
	// Return non-nil error if parsing fails
	reqdat, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request: %s", err)
		return err
	}
	err = json.Unmarshal(reqdat, typestruct)
	if err != nil {
		log.Printf("Error unmarshalling JSON: %s", err)
		return err
	}

	return nil
}

// HandlerFuncs that aren't methods
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	data := []byte("OK")

	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write(data)
}

// Middleware that aren't methods
func middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// Setup and run server
func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)

	port := "8080"
	filepathRoot := http.Dir(".")

	apiCfg := &apiConfig{Queries: dbQueries}

	fserver := http.FileServer(filepathRoot)
	appHandler := http.StripPrefix("/app", fserver)

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpsHandler)
	mux.HandleFunc("POST /api/users", apiCfg.usersHandler)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s", filepathRoot, port)
	log.Fatal(server.ListenAndServe())
	//defer server.Shutdown(context.Background())

}
