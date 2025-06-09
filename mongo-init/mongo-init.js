//mongo-init.js
db = db.getSiblingDB("demo_db");

db.roles.insertMany([
  {
    role_id: "user",
    permissions: [
      {
        path: "hr:payroll:view",
        regions: ["SEA"],
        except_countries: ["MM"]
      }
    ]
  },
  {
    role_id: "admin",
    permissions: [
      {
        path: "*:*:*",
        regions: ["GLOBAL"]
      }
    ]
  }
]);

db.items.insertMany([
  { name: "Item A", qty: 5 },
  { name: "Item B", qty: 10 }
]);
