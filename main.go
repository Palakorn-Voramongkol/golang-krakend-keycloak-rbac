package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient *mongo.Client
	mongoDB     *mongo.Database
)

// ------------------------------------
// JWT Parsing
// ------------------------------------

func parseToken(c *fiber.Ctx) (jwt.MapClaims, error) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid Authorization header format")
	}
	tokenString := parts[1]

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// ------------------------------------
// RBAC Types
// ------------------------------------

type Requirement struct {
	Path    string
	Country string
}

type Permission struct {
	Path            string   `bson:"path"`
	Regions         []string `bson:"regions"`
	Countries       []string `bson:"countries"`
	ExceptRegions   []string `bson:"except_regions"`
	ExceptCountries []string `bson:"except_countries"`
	ExceptPaths     []string `bson:"except_paths"`
}

type Role struct {
	RoleID      string       `bson:"role_id"`
	Permissions []Permission `bson:"permissions"`
}

type User struct {
	ID               string
	AllowedCountries []string
	Roles            []Role
}

// ------------------------------------
// RBAC Implementation
// ------------------------------------

func matchPath(pattern, target string) bool {
	p := strings.Split(pattern, ":")
	t := strings.Split(target, ":")
	if len(p) != len(t) {
		return false
	}
	for i := range p {
		if p[i] != "*" && !strings.EqualFold(p[i], t[i]) {
			return false
		}
	}
	return true
}

func contains(list []string, target string) bool {
	for _, v := range list {
		if strings.EqualFold(v, target) || v == "*" {
			return true
		}
	}
	return false
}

func regionMap() map[string][]string {
	return map[string][]string{
		"SEA":    {"TH", "SG", "MY", "PH", "VN", "MM"},
		"GLOBAL": {"*"},
	}
}

func isCountryPermitted(country string, perm Permission) bool {
	if contains(perm.ExceptCountries, country) {
		return false
	}
	for _, exRegion := range perm.ExceptRegions {
		if countries, ok := regionMap()[exRegion]; ok {
			if contains(countries, country) {
				return false
			}
		}
	}
	if contains(perm.Countries, country) {
		return true
	}
	for _, region := range perm.Regions {
		if region == "*" {
			return true
		}
		if countries, ok := regionMap()[region]; ok {
			if contains(countries, country) {
				return true
			}
		}
	}
	return false
}

func IsAllowed(user *User, req Requirement) bool {
	if !contains(user.AllowedCountries, req.Country) {
		return false
	}

	for _, role := range user.Roles {
		for _, perm := range role.Permissions {
			for _, exPath := range perm.ExceptPaths {
				if matchPath(exPath, req.Path) {
					return false
				}
			}
			if matchPath(perm.Path, req.Path) && isCountryPermitted(req.Country, perm) {
				return true
			}
		}
	}
	return false
}

// ------------------------------------
// JWT to User + Role Mapping
// ------------------------------------

func extractUser(claims jwt.MapClaims) (*User, error) {
	username := claims["preferred_username"].(string)
	rolesIface, ok := claims["roles"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("roles missing in token")
	}

	var roleIDs []string
	for _, r := range rolesIface {
		if s, ok := r.(string); ok {
			roleIDs = append(roleIDs, s)
		}
	}

	rolesCollection := mongoDB.Collection("roles")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var roles []Role
	countrySet := make(map[string]struct{})

	for _, roleID := range roleIDs {
		var role Role
		err := rolesCollection.FindOne(ctx, bson.M{"role_id": roleID}).Decode(&role)
		if err != nil {
			return nil, fmt.Errorf("role not found in database: %s", roleID)
		}
		for _, perm := range role.Permissions {
			for _, r := range perm.Regions {
				if r == "GLOBAL" {
					countrySet["*"] = struct{}{}
				} else {
					for _, c := range regionMap()[r] {
						countrySet[c] = struct{}{}
					}
				}
			}
		}
		roles = append(roles, role)
	}

	var countries []string
	for c := range countrySet {
		countries = append(countries, c)
	}

	return &User{
		ID:               username,
		AllowedCountries: countries,
		Roles:            roles,
	}, nil
}

// ------------------------------------
// Middleware
// ------------------------------------

func requirePermission(req Requirement) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, err := parseToken(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		user, err := extractUser(claims)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
		}
		if !IsAllowed(user, req) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied for: " + req.Path,
			})
		}
		c.Locals("user", user)
		return c.Next()
	}
}

// ------------------------------------
// Mongo Setup
// ------------------------------------

func initMongo() {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Mongo Connect error:", err)
	}
	if err = client.Ping(ctx, nil); err != nil {
		log.Fatal("Mongo Ping error:", err)
	}
	mongoClient = client
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "demo_db"
	}
	mongoDB = client.Database(dbName)
	log.Println("Connected to MongoDB:", mongoURI)
}

// ------------------------------------
// Main App
// ------------------------------------

func main() {
	initMongo()

	app := fiber.New()

	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "This is a public endpoint."})
	})

	app.Get("/profile", func(c *fiber.Ctx) error {
		claims, err := parseToken(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{
			"user":    claims["preferred_username"],
			"roles":   claims["roles"],
			"subject": claims["sub"],
		})
	})

	app.Get("/user/payroll/view", requirePermission(Requirement{
		Path:    "hr:payroll:view",
		Country: "TH",
	}), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Authorized to view payroll in Thailand"})
	})

	app.Get("/admin/items", requirePermission(Requirement{
		Path:    "admin:items:view",
		Country: "GLOBAL",
	}), func(c *fiber.Ctx) error {
		if mongoDB == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "MongoDB not initialized",
			})
		}

		collection := mongoDB.Collection("items")
		if collection == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "MongoDB collection 'items' not found",
			})
		}

		count, err := collection.CountDocuments(context.Background(), struct{}{})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":  "Database count error",
				"detail": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"message":     "Admin access to item count",
			"itemCountDB": count,
		})
	})

	log.Println("Server started on port 3000")
	log.Fatal(app.Listen(":3000"))
}
