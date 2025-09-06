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

	"github.com/CheeseFizz/Chirpy/internal/auth"
	"github.com/CheeseFizz/Chirpy/internal/database"
)

// apiConfig
// server metrics and handlers related to config and metrics
type apiConfig struct {
	fileserverHits atomic.Int32
	Queries        *database.Queries
	Secret         string
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type Response struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}

	req := &acceptFormat{}
	response := &Response{}

	w.Header().Set("Content-Type", "application/json")

	err := parseRequestJson(r, req)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return
	}

	hpw, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %s\n", err)
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	}

	userParams := database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hpw,
	}
	user, err := cfg.Queries.CreateUser(r.Context(), userParams)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	} else {
		response.Email = user.Email
		response.Id = user.ID
		response.Created_at = user.CreatedAt
		response.Created_at = user.UpdatedAt
	}

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	}

	w.WriteHeader(201)
	w.Write(dat)

}

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, r *http.Request) {
	type acceptFormat struct {
		Body string `json:"body"`
	}

	naughty := []string{"kerfuffle", "sharbert", "fornax"}

	// type Response struct {
	// 	Error string `json:"error,omitempty"`
	// 	Valid *bool  `json:"valid,omitempty"`
	// }
	type Response struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}

	var cleaned_body string

	req := &acceptFormat{}
	response := &Response{}

	w.Header().Set("Content-Type", "application/json")

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	user_id, err := auth.ValidateJWT(token, cfg.Secret)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	err = parseRequestJson(r, req)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Something went wrong"))
		return
	}

	if len(req.Body) > 140 {
		w.WriteHeader(400)
		w.Write([]byte("Chirp is too long"))
		return
	}

	cleaned_body = req.Body
	for _, word := range naughty {
		rx := fmt.Sprintf(`(?i)%s`, word)
		re := regexp.MustCompile(rx)
		cleaned_body = re.ReplaceAllString(cleaned_body, "****")
	}

	chirpParams := database.CreateChripParams{
		Body:   cleaned_body,
		UserID: user_id,
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

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(201)
	w.Write(dat)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	zero := make([]database.Chirp, 0)

	chirps, err := cfg.Queries.GetChirps(r.Context())
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(200)
			chirps = zero
		} else {
			w.WriteHeader(500)
			return
		}
	}
	dat, err := json.Marshal(chirps)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}

	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cid, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error parsing: %s", err)
		w.WriteHeader(500)
		return
	}
	chirp, err := cfg.Queries.GetChirp(r.Context(), cid)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(404)
			return
		} else {
			w.WriteHeader(500)
			return
		}
	}
	dat, err := json.Marshal(chirp)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}

	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type acceptFormat struct {
		Password           string `json:"password"`
		Email              string `json:"email"`
		Expires_in_seconds int    `json:"expires_in_seconds"`
	}

	type Response struct {
		Id         string    `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
		Token      string    `json:"token"`
	}

	req := &acceptFormat{}
	response := &Response{}

	w.Header().Set("Content-Type", "application/json")

	err := parseRequestJson(r, req)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}

	user, err := cfg.Queries.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}

	err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}

	if req.Expires_in_seconds == 0 || req.Expires_in_seconds > 3600 {
		req.Expires_in_seconds = 3600
	}

	token, err := auth.MakeJWT(user.ID, cfg.Secret, time.Duration(req.Expires_in_seconds)*time.Second)
	if err != nil {
		log.Printf("loginHandler: error getting token: %v", err)
		w.WriteHeader(500)
		return
	}

	response.Id = user.ID.String()
	response.Created_at = user.CreatedAt
	response.Updated_at = user.UpdatedAt
	response.Email = user.Email
	response.Token = token

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
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
func middlewareFuncLog(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next(w, r)
	})
}

// Setup and run server
func main() {
	// Load environment variables
	godotenv.Load()

	// Connect database
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)

	// Setup apiConfig
	apiCfg := &apiConfig{
		Queries: dbQueries,
		Secret:  os.Getenv("SECRET"),
	}

	// Setup Services and Server Mux
	port := "8080"
	filepathRoot := http.Dir(".")

	fserver := http.FileServer(filepathRoot)
	appHandler := http.StripPrefix("/app", fserver)

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))
	mux.HandleFunc("GET /admin/metrics", middlewareFuncLog(apiCfg.metricsHandler))
	mux.HandleFunc("GET /api/healthz", middlewareFuncLog(healthzHandler))
	mux.HandleFunc("POST /admin/reset", middlewareFuncLog(apiCfg.resetHandler))
	mux.HandleFunc("POST /api/chirps", middlewareFuncLog(apiCfg.chirpsHandler))
	mux.HandleFunc("GET /api/chirps", middlewareFuncLog(apiCfg.getChirpsHandler))
	mux.HandleFunc("GET /api/chirps/{chirpID}", middlewareFuncLog(apiCfg.getChirpHandler))
	mux.HandleFunc("POST /api/users", middlewareFuncLog(apiCfg.usersHandler))
	mux.HandleFunc("POST /api/login", middlewareFuncLog(apiCfg.loginHandler))

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s", filepathRoot, port)
	log.Fatal(server.ListenAndServe())
	//defer server.Shutdown(context.Background())

}
