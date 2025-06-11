// Connect to the correct database
db = db.getSiblingDB("demo_db");

// Define roles and their specific permissions
db.roles.insertMany([
  {
    // The 'user' role gets specific permissions for each path
    role_id: "user",
    permissions: [
      // Permission for the /user/profile endpoint
      {
        path: "hr:profile:view",
        regions: ["GLOBAL"]
      },
      // Permission for the /user endpoint
      {
        path: "hr:user:view",
        regions: ["GLOBAL"]
      },
      // Permission for the /user/payroll endpoint, specifically for Thailand
      {
        path: "hr:payroll:view",
        countries: ["TH"]
      }
    ]
  },
  {
    // The 'admin' role has wildcard access to everything, everywhere
    role_id: "admin",
    permissions: [
      {
        path: "*:*:*",
        regions: ["GLOBAL"]
      }
    ]
  }
]);

// Insert some sample items for the /admin/items endpoint
db.items.insertMany([
  { name: "Item A", qty: 5 },
  { name: "Item B", qty: 10 }
]);
