package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/genproto/googleapis/type/latlng"
	"google.golang.org/grpc/metadata"

	places "cloud.google.com/go/maps/places/apiv1"
	placespb "cloud.google.com/go/maps/places/apiv1/placespb"
)

type User struct {
	Id               int32        `json:"id"`
	Name             string       `json:"name"`
	Email            string       `json:"email"`
	Password         string       `json:"password,omitempty"`
	SavedRestaurants []Restaurant `json:"saved_restaurants"`
}

type Claims struct {
	UserId int32 `json:"user_id"`
	jwt.StandardClaims
}

type RestaurantsRequestBody struct {
	Lat          float64  `json:"lat"`
	Lng          float64  `json:"lng"`
	Radius       float64  `json:"radius"`
	PrimaryTypes []string `json:"primaryTypes"`
}

type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type Photo struct {
	Name     string `json:"name"`
	WidthPx  int    `json:"widthPx"`
	HeightPx int    `json:"heightPx"`
}

type Restaurant struct {
	Id               string    `json:"id"`
	Name             string    `json:"name"`
	Address          string    `json:"address"`
	Rating           float64   `json:"rating"`
	Location         *Location `json:"location"`
	Types            []string  `json:"types"`
	PrimaryType      string    `json:"primaryType"`
	PhoneNumber      string    `json:"phoneNumber"`
	WebsiteUri       *string   `json:"websiteUri"`
	EditorialSummary *string   `json:"editorialSummary"`
	GoogleMapsUri    *string   `json:"googleMapsUri"`
	Photo            *Photo    `json:"photo"`
	PriceLevel       int       `json:"priceLevel"`
}

type contextKey string

const (
	claimsContextKey contextKey = "claims"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

func RequestRestaurants(client *places.Client, db *sql.DB, ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Decode request body
		var body RestaurantsRequestBody
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Get the claims (authentication context)
		claims, ok := r.Context().Value(claimsContextKey).(*Claims)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userId := claims.UserId

		// Get the user's saved restaurants from the database
		var user User
		var savedRestaurantsJSON []byte
		err = db.QueryRow("SELECT id, name, email, saved_restaurants FROM users WHERE id = $1", userId).Scan(&user.Id, &user.Name, &user.Email, &savedRestaurantsJSON)
		if err != nil {
			http.Error(w, "Failed to get saved restaurants", http.StatusInternalServerError)
			return
		}

		// Unmarshal the JSON data into the SavedRestaurants field
		err = json.Unmarshal(savedRestaurantsJSON, &user.SavedRestaurants)
		if err != nil {
			http.Error(w, "Failed to unmarshal saved restaurants", http.StatusInternalServerError)
			return
		}

		// Create a set of saved restaurant IDs for efficient lookup
		savedRestaurantIds := make(map[string]bool)
		for _, restaurant := range user.SavedRestaurants {
			savedRestaurantIds[restaurant.Id] = true
		}

		// Create the location restriction
		locationRestriction := &placespb.SearchNearbyRequest_LocationRestriction{
			Type: &placespb.SearchNearbyRequest_LocationRestriction_Circle{
				Circle: &placespb.Circle{
					Center: &latlng.LatLng{
						Latitude:  body.Lat,
						Longitude: body.Lng,
					},
					Radius: body.Radius,
				},
			},
		}

		// Define request struct
		req := &placespb.SearchNearbyRequest{
			LanguageCode:         "en",
			RegionCode:           "US",
			IncludedPrimaryTypes: body.PrimaryTypes,
			MaxResultCount:       9,
			LocationRestriction:  locationRestriction,
		}

		// Call Google Places API
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
			"X-Goog-FieldMask",
			"places.id,places.displayName,places.formattedAddress,places.rating,places.location,places.types,places.primaryType,places.nationalPhoneNumber,places.websiteUri,places.editorialSummary,places.googleMapsUri,places.photos,places.priceLevel",
		))
		resp, err := client.SearchNearby(ctx, req)
		if err != nil {
			log.Printf("Error searching nearby: %v", err)
			http.Error(w, "Failed to search for restaurants", http.StatusInternalServerError)
			return
		}

		// Create a slice to hold the restaurant data
		restaurants := make([]map[string]interface{}, 0, len(resp.Places))

		// Extract relevant information from each place
		for _, place := range resp.Places {
			restaurantId := place.Id
			if savedRestaurantIds[restaurantId] {
				continue
			}
			var photo map[string]interface{}
			if len(place.Photos) > 0 {
				firstPhoto := place.Photos[0]
				photo = map[string]interface{}{
					"name":     firstPhoto.Name,
					"widthPx":  firstPhoto.WidthPx,
					"heightPx": firstPhoto.HeightPx,
				}
			}

			restaurant := map[string]interface{}{
				"id":               place.Id,
				"name":             place.DisplayName.GetText(),
				"address":          place.FormattedAddress,
				"rating":           place.Rating,
				"location":         place.Location,
				"types":            place.Types,
				"primaryType":      place.PrimaryType,
				"phoneNumber":      place.NationalPhoneNumber,
				"websiteUri":       place.WebsiteUri,
				"editorialSummary": place.EditorialSummary.GetText(),
				"googleMapsUri":    place.GoogleMapsUri,
				"photo":            photo,
				"priceLevel":       place.PriceLevel,
			}
			restaurants = append(restaurants, restaurant)
		}

		// Marshal the response into JSON
		jsonResponse, err := json.Marshal(restaurants)
		if err != nil {
			log.Printf("Error marshaling JSON: %v", err)
			http.Error(w, "Failed to process restaurant data", http.StatusInternalServerError)
			return
		}

		// Send the response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonResponse)
	}
}

func RequestRestaurantsNoAuth(client *places.Client, ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body RestaurantsRequestBody
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Create the location restriction
		locationRestriction := &placespb.SearchNearbyRequest_LocationRestriction{
			Type: &placespb.SearchNearbyRequest_LocationRestriction_Circle{
				Circle: &placespb.Circle{
					Center: &latlng.LatLng{
						Latitude:  body.Lat,
						Longitude: body.Lng,
					},
					Radius: body.Radius,
				},
			},
		}

		// Define request struct
		req := &placespb.SearchNearbyRequest{
			LanguageCode:         "en",
			RegionCode:           "US",
			IncludedPrimaryTypes: body.PrimaryTypes,
			MaxResultCount:       9,
			LocationRestriction:  locationRestriction,
		}

		// Call Google Places API
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
			"X-Goog-FieldMask",
			"places.id,places.displayName,places.formattedAddress,places.rating,places.location,places.types,places.primaryType,places.nationalPhoneNumber,places.websiteUri,places.editorialSummary,places.googleMapsUri,places.photos,places.priceLevel",
		))
		resp, err := client.SearchNearby(ctx, req)
		if err != nil {
			log.Printf("Error searching nearby: %v", err)
			http.Error(w, "Failed to search for restaurants", http.StatusInternalServerError)
			return
		}

		// Create a slice to hold the restaurant data
		restaurants := make([]map[string]interface{}, 0, len(resp.Places))

		// Extract relevant information from each place
		for _, place := range resp.Places {
			var photo map[string]interface{}
			if len(place.Photos) > 0 {
				firstPhoto := place.Photos[0]
				photo = map[string]interface{}{
					"name":     firstPhoto.Name,
					"widthPx":  firstPhoto.WidthPx,
					"heightPx": firstPhoto.HeightPx,
				}
			}

			restaurant := map[string]interface{}{
				"id":               place.Id,
				"name":             place.DisplayName.GetText(),
				"address":          place.FormattedAddress,
				"rating":           place.Rating,
				"location":         place.Location,
				"types":            place.Types,
				"primaryType":      place.PrimaryType,
				"phoneNumber":      place.NationalPhoneNumber,
				"websiteUri":       place.WebsiteUri,
				"editorialSummary": place.EditorialSummary.GetText(),
				"googleMapsUri":    place.GoogleMapsUri,
				"photo":            photo,
				"priceLevel":       place.PriceLevel,
			}
			restaurants = append(restaurants, restaurant)
		}

		jsonResponse, err := json.Marshal(restaurants)
		if err != nil {
			log.Printf("Error marshaling JSON: %v", err)
			http.Error(w, "Failed to process restaurant data", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonResponse)
	}
}

func GetSavedRestaurants(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the user's ID from the JWT claims
		claims, ok := r.Context().Value(claimsContextKey).(*Claims)
		if !ok || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userId := claims.UserId

		// Get the user's saved restaurants from the database
		var savedRestaurantsJSON []byte
		err := db.QueryRow("SELECT saved_restaurants FROM users WHERE id = $1", userId).Scan(&savedRestaurantsJSON)
		if err != nil {
			http.Error(w, "Failed to get saved restaurants", http.StatusInternalServerError)
			return
		}

		// Unmarshal the JSON data into a slice of Restaurant
		var savedRestaurants []Restaurant
		err = json.Unmarshal(savedRestaurantsJSON, &savedRestaurants)
		if err != nil {
			http.Error(w, "Failed to unmarshal saved restaurants", http.StatusInternalServerError)
			return
		}

		// Respond with the saved restaurants
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(savedRestaurants)
	}
}

func PutSavedRestaurant(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the JSON request body to get the PlaceID
		var body Restaurant
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Extract the user's ID from the JWT claims
		claims, ok := r.Context().Value(claimsContextKey).(*Claims)
		if !ok || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userId := claims.UserId

		// Get the user's saved restaurants from the database
		var user User
		var savedRestaurantsJSON []byte
		err = db.QueryRow("SELECT id, name, email, saved_restaurants FROM users WHERE id = $1", userId).Scan(&user.Id, &user.Name, &user.Email, &savedRestaurantsJSON)
		if err != nil {
			http.Error(w, "Failed to get saved restaurants", http.StatusInternalServerError)
			return
		}

		// Unmarshal the JSON data into the SavedRestaurants field
		err = json.Unmarshal(savedRestaurantsJSON, &user.SavedRestaurants)
		if err != nil {
			http.Error(w, "Failed to unmarshal saved restaurants", http.StatusInternalServerError)
			return
		}

		// Check if place id is already saved
		for _, restaurant := range user.SavedRestaurants {
			if restaurant.Id == body.Id {
				http.Error(w, "Place already in saved list", http.StatusBadRequest)
				return
			}
		}

		// Append the new restaurant to the user's saved restaurants
		user.SavedRestaurants = append(user.SavedRestaurants, body)

		// Marshal the updated saved restaurants back into JSON
		updatedSavedRestaurantsJSON, err := json.Marshal(user.SavedRestaurants)
		if err != nil {
			http.Error(w, "Failed to marshal updated saved restaurants", http.StatusInternalServerError)
			return
		}

		// Update the user's saved restaurants in the database
		_, err = db.Exec("UPDATE users SET saved_restaurants = $1 WHERE id = $2", updatedSavedRestaurantsJSON, userId)
		if err != nil {
			http.Error(w, "Failed to update saved restaurants", http.StatusInternalServerError)
			return
		}

		// Respond with success
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Saved restaurants updated successfully"})
	}
}

func DeleteSavedRestaurant(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the JSON request body to get the PlaceID of the restaurant to delete
		var body struct {
			RestaurantID string `json:"restaurant_id"`
		}
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Extract the user's ID from the JWT claims
		claims, ok := r.Context().Value(claimsContextKey).(*Claims)
		if !ok || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userId := claims.UserId

		// Get the user's saved restaurants from the database
		var user User
		var savedRestaurantsJSON []byte
		err = db.QueryRow("SELECT id, name, email, saved_restaurants FROM users WHERE id = $1", userId).Scan(&user.Id, &user.Name, &user.Email, &savedRestaurantsJSON)
		if err != nil {
			http.Error(w, "Failed to get saved restaurants", http.StatusInternalServerError)
			return
		}

		// Unmarshal the JSON data into the SavedRestaurants field
		err = json.Unmarshal(savedRestaurantsJSON, &user.SavedRestaurants)
		if err != nil {
			http.Error(w, "Failed to unmarshal saved restaurants", http.StatusInternalServerError)
			return
		}

		// Find and remove the restaurant with the specified ID from the SavedRestaurants slice
		updatedRestaurants := []Restaurant{}
		restaurantFound := false
		for _, restaurant := range user.SavedRestaurants {
			if restaurant.Id != body.RestaurantID {
				updatedRestaurants = append(updatedRestaurants, restaurant)
			} else {
				restaurantFound = true
			}
		}

		if !restaurantFound {
			http.Error(w, "Restaurant not found in saved list", http.StatusNotFound)
			return
		}

		// Marshal the updated saved restaurants back into JSON
		updatedSavedRestaurantsJSON, err := json.Marshal(updatedRestaurants)
		if err != nil {
			http.Error(w, "Failed to marshal updated saved restaurants", http.StatusInternalServerError)
			return
		}

		// Update the user's saved restaurants in the database
		_, err = db.Exec("UPDATE users SET saved_restaurants = $1 WHERE id = $2", updatedSavedRestaurantsJSON, userId)
		if err != nil {
			http.Error(w, "Failed to update saved restaurants", http.StatusInternalServerError)
			return
		}

		// Respond with success
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Restaurant deleted successfully"})
	}
}

func CreateTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password VARCHAR(100) NOT NULL,
			saved_restaurants JSONB
		);
	`)
	return err
}

func SignUp(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (name, email, password, saved_restaurants) VALUES ($1, $2, $3, $4)",
			user.Name, user.Email, string(hashedPassword), `[]`)
		if err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
	}
}

func Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var dbUser User
		err := db.QueryRow("SELECT id, password FROM users WHERE email = $1", user.Email).Scan(&dbUser.Id, &dbUser.Password)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			UserId: dbUser.Id,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Error creating token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set the token cookie with an empty value and an expired time
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   "",
			Expires: time.Now().Add(-1 * time.Hour),
			Path:    "/",
		})

		// Send a response to the user
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
	}
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		tokenStr := cookie.Value
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func EnableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the specific origin instead of using a wildcard
		w.Header().Set("Access-Control-Allow-Origin", "https://foodie.antoara.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func JsonContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func main() {
	ctx := context.Background()
	client, err := places.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create Places client: %v", err)
	}
	defer client.Close()

	// Connect to postgres database
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	if err := CreateTables(db); err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	// Create router
	router := mux.NewRouter()
	router.HandleFunc("/api/signup", SignUp(db)).Methods("POST")
	router.HandleFunc("/api/login", Login(db)).Methods("POST")
	router.HandleFunc("/api/logout", Logout()).Methods("POST")
	router.HandleFunc("/api/restaurants-no-auth", RequestRestaurantsNoAuth(client, ctx)).Methods("POST")
	router.HandleFunc("/api/restaurants", AuthMiddleware(RequestRestaurants(client, db, ctx))).Methods("POST")
	router.HandleFunc("/api/put-saved-restaurant", AuthMiddleware(PutSavedRestaurant(db))).Methods("PUT")
	router.HandleFunc("/api/delete-saved-restaurant", AuthMiddleware(DeleteSavedRestaurant(db))).Methods("DELETE")
	router.HandleFunc("/api/get-saved-restaurants", AuthMiddleware(GetSavedRestaurants(db))).Methods("GET")

	// Wrap the router with CORS and JSON content type middlewares
	enhancedRouter := EnableCORS(JsonContentTypeMiddleware(router))

	// Start server
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", enhancedRouter))
}
