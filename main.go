// main.go
//
// Secure Fiber-based Go API using JWT authentication with Role-Based Access Control (RBAC).
// Integrates MongoDB to load role-permission mappings, with validation middleware to enforce
// access rules per user, role, and region/country-level restrictions.

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

/*
parseToken extracts the JWT token from the Authorization header
and parses its claims without verifying the signature. This is safe because
the signature has already been verified by the KrakenD API Gateway.
*/
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

// Requirement defines a required permission path and country for an endpoint.
type Requirement struct {
	Path    string
	Country string
}

// Permission represents a single RBAC rule stored in MongoDB for a role.
type Permission struct {
	Path            string   `bson:"path"`
	Regions         []string `bson:"regions"`
	Countries       []string `bson:"countries"`
	ExceptRegions   []string `bson:"except_regions"`
	ExceptCountries []string `bson:"except_countries"`
	ExceptPaths     []string `bson:"except_paths"`
}

// Role represents a user role containing a list of permissions.
type Role struct {
	RoleID      string       `bson:"role_id"`
	Permissions []Permission `bson:"permissions"`
}

// User is a temporary struct representing the authenticated user,
// compiled with their roles and all countries they are permitted to access.
type User struct {
	ID               string
	AllowedCountries []string
	Roles            []Role
}

// ------------------------------------
// RBAC Implementation
// ------------------------------------

/*
matchPath compares a permission path pattern (e.g., "hr:profile:*")
against a target request path (e.g., "hr:profile:view") using wildcard matching.
*/
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

/*
contains checks if a target string exists in a list of strings,
with case-insensitivity and support for the wildcard character '*'.
*/
func contains(list []string, target string) bool {
	for _, v := range list {
		if strings.EqualFold(v, target) || v == "*" {
			return true
		}
	}
	return false
}

/*
regionMap returns a static mapping of region codes (e.g., "ASIA")
to their corresponding lists of ISO-2 country codes.
*/
func regionMap() map[string][]string {
	return map[string][]string{
		// Africa (all African countries)
		"AFRICA": {
			"DZ", "AO", "BJ", "BW", "BF", "BI", "CV", "CM", "CF", "TD", "KM", "CG", "CD", "CI",
			"DJ", "EG", "GQ", "ER", "SZ", "ET", "GA", "GM", "GH", "GN", "GW", "KE", "LS", "LR",
			"LY", "MG", "MW", "ML", "MR", "MU", "MA", "MZ", "NA", "NE", "NG", "RW", "ST", "SN",
			"SC", "SL", "SO", "ZA", "SS", "SD", "TZ", "TG", "TN", "UG", "EH", "ZM", "ZW",
		},
		// Asia (all Asian countries, including Middle East)
		"ASIA": {
			"AF", "AM", "AZ", "BH", "BD", "BT", "BN", "KH", "CN", "CY", "GE", "IN", "ID", "IR",
			"IQ", "IL", "JP", "JO", "KZ", "KW", "KG", "LA", "LB", "MY", "MV", "MN", "MM", "NP",
			"KP", "OM", "PK", "PS", "PH", "QA", "RU", "SA", "SG", "KR", "LK", "SY", "TW", "TJ",
			"TH", "TL", "TR", "TM", "AE", "UZ", "VN", "YE",
		},
		// Europe
		"EUROPE": {
			"AL", "AD", "AT", "BY", "BE", "BA", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
			"DE", "GR", "HU", "IS", "IE", "IT", "LV", "LI", "LT", "LU", "MT", "MD", "MC", "ME",
			"NL", "MK", "NO", "PL", "PT", "RO", "SM", "RS", "SK", "SI", "ES", "SE", "CH", "UA", "UK", "VA",
		},
		// North America
		"NORTH_AMERICA": {
			"AG", "BS", "BB", "BZ", "CA", "CR", "CU", "DM", "DO", "SV", "GD", "GT", "HT", "HN",
			"JM", "MX", "NI", "PA", "KN", "LC", "VC", "TT", "US",
		},
		// South America
		"SOUTH_AMERICA": {
			"AR", "BO", "BR", "CL", "CO", "EC", "GY", "PY", "PE", "SR", "UY", "VE",
		},
		// Oceania
		"OCEANIA": {
			"AU", "FJ", "KI", "MH", "FM", "NR", "NZ", "PW", "PG", "WS", "SB", "TO", "TV", "VU",
		},
		// Antarctica
		"ANTARCTICA": {"AQ"},
		// Global wildcard for all countries
		"GLOBAL": {"*"},
	}
}

/*
isCountryPermitted evaluates if a specific country is allowed by a permission rule,
taking into account included/excluded countries and regions.
*/
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
		if region == "*" || region == "GLOBAL" {
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

/*
IsAllowed is the core RBAC logic function. It checks if a user has permission
to access a resource based on their roles and the endpoint's requirements.
*/
func IsAllowed(user *User, req Requirement) bool {
	// First, check if the required country is in the user's pre-calculated list of allowed countries.
	if !contains(user.AllowedCountries, req.Country) && req.Country != "GLOBAL" {
		return false
	}

	// Then, check if any of the user's roles grant permission for the required path and country.
	for _, role := range user.Roles {
		for _, perm := range role.Permissions {
			// Check for explicit path exclusions first.
			for _, exPath := range perm.ExceptPaths {
				if matchPath(exPath, req.Path) {
					return false // Deny if path is explicitly excluded.
				}
			}
			// Grant access if the path and country are permitted by the rule.
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

/*
extractUser parses JWT claims, retrieves the associated roles from MongoDB,
and builds a User object with all permissions and a computed list of allowed countries.
*/
func extractUser(claims jwt.MapClaims) (*User, error) {
	username, ok := claims["preferred_username"].(string)
	if !ok {
		return nil, fmt.Errorf("preferred_username missing or not a string in token")
	}
	rolesIface, ok := claims["roles"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("roles claim missing or in wrong format")
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
			// Log the actual error for debugging but return a generic message to the client.
			log.Printf("Failed to find role '%s' in database: %v", roleID, err)
			return nil, fmt.Errorf("permission check failed: could not resolve user roles")
		}

		// Calculate the set of all countries this user is allowed to access.
		for _, perm := range role.Permissions {
			for _, r := range perm.Regions {
				if r == "GLOBAL" || r == "*" {
					countrySet["*"] = struct{}{}
				} else if countries, ok := regionMap()[r]; ok {
					for _, c := range countries {
						countrySet[c] = struct{}{}
					}
				}
			}
			for _, c := range perm.Countries {
				countrySet[c] = struct{}{}
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

/*
requirePermission returns a Fiber middleware. It parses the JWT, builds the user's
permission profile from MongoDB, and denies access if the required permissions are not met.
*/
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
				"error": "Access denied. You do not have permission for this resource.",
			})
		}
		// Store the resolved user object in the context for handlers to use.
		c.Locals("user", user)
		return c.Next()
	}
}

// ------------------------------------
// Mongo Setup
// ------------------------------------

/*
initMongo initializes the connection to the MongoDB database using an
environment variable for the URI and a default fallback.
*/
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

/*
main is the entry point of the application. It initializes the database connection,
sets up the Fiber HTTP routes and middleware, and starts the server.
*/
func main() {
	initMongo()

	app := fiber.New()

	// Public endpoint, does not require authentication or permissions.
	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "This is a public endpoint."})
	})

	// Profile endpoint, protected by RBAC middleware.
	app.Get("/user/profile", requirePermission(Requirement{
		Path:    "hr:profile:view",
		Country: "GLOBAL",
	}), func(c *fiber.Ctx) error {
		// Retrieve the user object already processed by the middleware.
		user := c.Locals("user").(*User)

		// Construct the response with detailed user info.
		return c.JSON(fiber.Map{
			"user":              user.ID,
			"roles":             user.Roles, // This will be the full role object from Mongo.
			"allowed_countries": user.AllowedCountries,
		})
	})

	// User data endpoint, protected by RBAC middleware.
	app.Get("/user", requirePermission(Requirement{
		Path:    "hr:user:view",
		Country: "GLOBAL",
	}), func(c *fiber.Ctx) error {
		// The 'requirePermission' middleware already parsed the user and stored it.
		// We can retrieve it from the context.
		user := c.Locals("user").(*User)

		// Return general, non-sensitive user data.
		return c.JSON(fiber.Map{
			"username":          user.ID,
			"allowed_countries": user.AllowedCountries,
		})
	})

	// Payroll endpoint with country-specific permission requirement.
	app.Get("/user/payroll", requirePermission(Requirement{
		Path:    "hr:payroll:view",
		Country: "TH",
	}), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Authorized to view payroll in Thailand"})
	})

	// Admin-only endpoint for viewing item data.
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
