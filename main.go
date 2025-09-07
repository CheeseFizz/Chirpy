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
	"sort"
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
	PolkaKey       string
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
		database.User
	}

	req := &acceptFormat{}

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
	}
	response := &Response{
		user,
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

func (cfg *apiConfig) putUsersHandler(w http.ResponseWriter, r *http.Request) {
	type acceptFormat struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	req := &acceptFormat{}

	w.Header().Set("Content-Type", "application/json")

	atokenstr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	u_id, err := auth.ValidateJWT(atokenstr, cfg.Secret)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	err = parseRequestJson(r, req)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return
	}

	hpw, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %s\n", err)
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	}

	userParams := database.UpdateUserParams{
		Email:          req.Email,
		HashedPassword: hpw,
		ID:             u_id,
	}
	user, err := cfg.Queries.UpdateUser(r.Context(), userParams)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return
	}

	dat, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	}

	w.WriteHeader(200)
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
	var err error
	var chirps []database.Chirp

	sort_str := r.URL.Query().Get("sort")
	if sort_str == "" || sort_str != "desc" {
		sort_str = "asc"
	}

	u_id_str := r.URL.Query().Get("author_id")
	if u_id_str != "" {
		var u_id uuid.UUID
		u_id, err = uuid.Parse(u_id_str)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		chirps, err = cfg.Queries.GetChirpsByUser(r.Context(), u_id)
	} else {
		chirps, err = cfg.Queries.GetChirps(r.Context())
	}

	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(200)
			chirps = zero
		} else {
			w.WriteHeader(500)
			return
		}
	}

	if sort_str == "asc" {
		sort.Slice(
			chirps,
			func(i, j int) bool {
				return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
			},
		)
	} else {
		sort.Slice(
			chirps,
			func(i, j int) bool {
				return chirps[j].CreatedAt.Before(chirps[i].CreatedAt)
			},
		)
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

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	atokenstr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	u_id, err := auth.ValidateJWT(atokenstr, cfg.Secret)
	if err != nil {
		w.WriteHeader(401)
		return
	}

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

	if u_id != chirp.UserID {
		w.WriteHeader(403)
		return
	}

	err = cfg.Queries.DeleteChirp(r.Context(), chirp.ID)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type acceptFormat struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type Response struct {
		database.User
		Token         string `json:"token"`
		Refresh_token string `json:"refresh_token"`
	}

	req := &acceptFormat{}

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

	atoken, err := auth.MakeJWT(user.ID, cfg.Secret, time.Hour)
	if err != nil {
		log.Printf("loginHandler: error making access token: %v", err)
		w.WriteHeader(500)
		return
	}

	rtokenstr, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("loginHandler: error making refresh token: %v", err)
		w.WriteHeader(500)
		return
	}

	crtParams := database.CreateRefreshTokenParams{
		Token:     rtokenstr,
		ExpiresAt: time.Now().Add(time.Duration(60*24) * time.Hour),
		UserID:    user.ID,
	}
	rtoken, err := cfg.Queries.CreateRefreshToken(r.Context(), crtParams)
	if err != nil {
		log.Printf("loginHandler: error making refresh token: %v", err)
		w.WriteHeader(500)
		return
	}

	response := &Response{
		user,
		atoken,
		rtoken.Token,
	}

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
	w.Write(dat)

}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Token string `json:"token"`
	}
	response := &Response{}
	w.Header().Set("Content-Type", "application/json")

	rtokenstr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	rtoken, err := cfg.Queries.GetRefreshToken(r.Context(), rtokenstr)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	if rtoken.ExpiresAt.Compare(time.Now()) <= 0 || rtoken.RevokedAt.Valid {
		w.WriteHeader(401)
		return
	}

	user, err := cfg.Queries.GetUserFromRefreshToken(r.Context(), rtokenstr)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	atoken, err := auth.MakeJWT(user.ID, cfg.Secret, time.Hour)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	response.Token = atoken

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {

	rtokenstr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	err = cfg.Queries.RevokeRefreshToken(r.Context(), rtokenstr)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) polkaWHHandler(w http.ResponseWriter, r *http.Request) {
	type dataFormat struct {
		User_id string `json:"user_id"`
	}

	type acceptFormat struct {
		Event string     `json:"event"`
		Data  dataFormat `json:"data"`
	}

	req := &acceptFormat{}

	rkey, err := auth.GetAPIKey(r.Header)
	if err != nil || rkey != cfg.PolkaKey {
		w.WriteHeader(401)
		return
	}

	err = parseRequestJson(r, req)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return
	}

	if req.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	u_id, err := uuid.Parse(req.Data.User_id)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return
	}
	setUserParams := database.SetUserRedParams{
		ID:          u_id,
		IsChirpyRed: true,
	}

	err = cfg.Queries.SetUserRed(r.Context(), setUserParams)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
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
		Queries:  dbQueries,
		Secret:   os.Getenv("SECRET"),
		PolkaKey: os.Getenv("POLKA_KEY"),
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
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", middlewareFuncLog(apiCfg.deleteChirpHandler))
	mux.HandleFunc("POST /api/users", middlewareFuncLog(apiCfg.usersHandler))
	mux.HandleFunc("PUT /api/users", middlewareFuncLog(apiCfg.putUsersHandler))
	mux.HandleFunc("POST /api/login", middlewareFuncLog(apiCfg.loginHandler))
	mux.HandleFunc("POST /api/refresh", middlewareFuncLog(apiCfg.refreshHandler))
	mux.HandleFunc("POST /api/revoke", middlewareFuncLog(apiCfg.revokeHandler))
	mux.HandleFunc("POST /api/polka/webhooks", middlewareFuncLog(apiCfg.polkaWHHandler))

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s", filepathRoot, port)
	log.Fatal(server.ListenAndServe())
	//defer server.Shutdown(context.Background())

}
