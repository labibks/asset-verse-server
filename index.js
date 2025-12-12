// index.js
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

// Optional: stripe (install করলে চালবে)
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
}

const port = process.env.PORT || 3000;
const app = express();

// Middleware
app.use(cors());

// ⚠️ IMPORTANT: Webhook MUST use raw body - add BEFORE express.json()
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(400).send("Webhook not configured");
    }

    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature mismatch:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const hrEmail = session.metadata.hrEmail;
      const packageId = session.metadata.packageId;
      const amount = session.amount_total / 100;

      // Save payment record
      await payments.insertOne({
        hrEmail,
        packageId,
        amount,
        transactionId: session.payment_intent,
        paymentDate: new Date(),
        status: "completed",
      });

      // Update HR packageLimit immediately
      const pkg = await packages.findOne({ _id: new ObjectId(packageId) });
      if (pkg) {
        await users.updateOne(
          { email: hrEmail },
          {
            $set: {
              packageLimit: pkg.employeeLimit,
              subscription: pkg.name,
            },
          }
        );
      }
    }

    res.json({ received: true });
  }
);

// Now add JSON middleware for all other routes
app.use(express.json());

// MongoDB URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.mvyw8xi.mongodb.net/?appName=Cluster0`;

// MongoClient
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

// JWT secret (env এ সেট করতে হবে)
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

// ----------------- Helpers -----------------

// token create
function createToken(user) {
  const payload = {
    id: user._id ? user._id.toString() : user.id,
    email: user.email,
    role: user.role,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d", algorithm: "HS256" });
}

const admin = require("firebase-admin");
let serviceAccount;
try {
  // serviceAccount = require("./assetverse-client-firebasse-adminsdk.json");

  // const serviceAccount = require("./firebase-admin-key.json");

  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
    "utf8"
  );
  const serviceAccount = JSON.parse(decoded);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log("✅ Firebase admin initialized");
} catch (err) {
  console.warn(
    "⚠️ Firebase service account not found — skipping admin.initializeApp(). Provide `assetverse-client-firebasse-adminsdk.json` in the project root to enable Firebase admin features."
  );
}
// verifyToken middleware
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    // attach user info to req
    req.user = decoded;
    // optionally fetch fresh user from DB
    const user = await db.collection("users").findOne({ email: decoded.email });
    if (!user) return res.status(401).json({ error: "User not found" });
    req.currentUser = user;
    next();
  } catch (err) {
    console.error("verifyToken error:", err);
    return res.status(401).json({ error: "Token invalid or expired" });
  }
}

// verifyHR middleware
function verifyHR(req, res, next) {
  if (!req.currentUser) return res.status(401).json({ error: "Unauthorized" });
  if (req.currentUser.role !== "hr")
    return res.status(403).json({ error: "HR only route" });
  next();
}

const validateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.sendStatus(403); // Forbidden
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
};

// ----------------- Main Function -----------------
async function runServer() {
  try {
    // 1️⃣ Connect to DB
    await client.connect();
    db = client.db("AssetVerseDB");
    console.log("✅ Database connected successfully!");

    // 2️⃣ Create Collections variables
    const users = db.collection("users");
    const affiliations = db.collection("employeeAffiliations");
    const assets = db.collection("assets");
    const requests = db.collection("requests");
    const assignedAssets = db.collection("assignedAssets");
    const packages = db.collection("packages");
    const payments = db.collection("payments");

    console.log("✅ Collections ready!");

    // ------------------------------
    // 3️⃣ Seed Data (Auto Insert, but hash passwords)
    // ------------------------------
    async function seedData() {
      // USERS (hash password before insert)
      if ((await users.countDocuments()) === 0) {
        const salt = await bcrypt.genSalt(10);
        const hrPassword = await bcrypt.hash("123456", salt);
        const empPassword = await bcrypt.hash("123456", salt);

        await users.insertMany([
          {
            name: "Admin HR",
            companyName: "TestCompany",
            email: "hr@test.com",
            password: hrPassword,
            role: "hr",
            packageLimit: 5,
            currentEmployees: 0,
            subscription: "basic",
            createdAt: new Date(),
          },
          {
            name: "Employee One",
            email: "emp1@test.com",
            password: empPassword,
            role: "employee",
            createdAt: new Date(),
          },
        ]);
        console.log("🌱 Users seeded (passwords hashed)");
      }

      // PACKAGES
      if ((await packages.countDocuments()) === 0) {
        await packages.insertMany([
          {
            name: "Basic",
            employeeLimit: 5,
            price: 5,
            features: [
              "Asset Tracking",
              "Employee Management",
              "Basic Support",
            ],
          },
          {
            name: "Standard",
            employeeLimit: 10,
            price: 8,
            features: [
              "All Basic features",
              "Advanced Analytics",
              "Priority Support",
            ],
          },
          {
            name: "Premium",
            employeeLimit: 20,
            price: 15,
            features: [
              "All Standard features",
              "Custom Branding",
              "24/7 Support",
            ],
          },
        ]);
        console.log("🌱 Packages seeded");
      }

      // ASSETS
      if ((await assets.countDocuments()) === 0) {
        await assets.insertMany([
          {
            productName: "Laptop Dell",
            productImage: "",
            productType: "Returnable",
            productQuantity: 10,
            availableQuantity: 10,
            hrEmail: "hr@test.com",
            companyName: "TestCompany",
            dateAdded: new Date(),
          },
          {
            productName: "Office Chair",
            productImage: "",
            productType: "Non-returnable",
            productQuantity: 20,
            availableQuantity: 20,
            hrEmail: "hr@test.com",
            companyName: "TestCompany",
            dateAdded: new Date(),
          },
        ]);
        console.log("🌱 Assets seeded");
      }
    }

    await seedData();

    // ------------------------------
    // 4️⃣ Routes
    // ------------------------------

    // Root
    app.get("/", (req, res) => {
      res.send("AssetVerse Server Running...");
    });

    // ------------------ AUTH (Register / Login) ------------------

    // Register (employee or hr) -> body must include role: "employee" or "hr"
    app.post("/auth/register", async (req, res) => {
      try {
        const {
          name,
          email,
          password,
          dateOfBirth,
          role,
          companyName,
          companyLogo,
        } = req.body;
        if (!name || !email || !password || !role) {
          return res
            .status(400)
            .json({ error: "name, email, password, role are required" });
        }

        const existing = await users.findOne({ email });
        if (existing)
          return res.status(400).json({ error: "User already exists" });

        const salt = await bcrypt.genSalt(10);
        const hashed = await bcrypt.hash(password, salt);

        const newUser = {
          name,
          email,
          password: hashed,
          dateOfBirth: dateOfBirth || null,
          role,
          profileImage: "",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        if (role === "hr") {
          newUser.companyName = companyName || "Company";
          newUser.companyLogo = companyLogo || "";
          newUser.packageLimit = 5;
          newUser.currentEmployees = 0;
          newUser.subscription = "basic";
        }

        const result = await users.insertOne(newUser);
        const insertedUser = await users.findOne({ _id: result.insertedId });
        const token = createToken(insertedUser);

        return res.json({
          success: true,
          token,
          user: {
            email: insertedUser.email,
            name: insertedUser.name,
            role: insertedUser.role,
          },
        });
      } catch (err) {
        console.error("register err:", err);
        res.status(500).json({ error: "Registration failed" });
      }
    });

    // Login
    app.post("/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        if (!email || !password)
          return res.status(400).json({ error: "Email and password required" });

        const user = await users.findOne({ email });
        if (!user)
          return res.status(400).json({ error: "Invalid credentials" });

        const match = await bcrypt.compare(password, user.password);
        if (!match)
          return res.status(400).json({ error: "Invalid credentials" });

        const token = createToken(user);
        // return token and basic user info
        return res.json({
          success: true,
          token,
          user: { email: user.email, name: user.name, role: user.role },
        });
      } catch (err) {
        console.error("login err:", err);
        res.status(500).json({ error: "Login failed" });
      }
    });

    // Protected example: get current user
    app.get("/me", verifyToken, async (req, res) => {
      const user = req.currentUser;
      // Do not send password
      delete user.password;
      res.json({ user });
    });

    // Example route using the validateToken middleware
    app.get("/protected", validateToken, (req, res) => {
      res.json({ message: "This is a protected route", user: req.user });
    });

    // ------------------ ASSETS ------------------

    // Public: get assets (with optional query ?available=true)

    const { ObjectId } = require("mongodb");

    // Get all assets (HR + employee)
    app.get("/assets", verifyToken, async (req, res) => {
      try {
        const list = await assets.find().toArray();
        res.json({ success: true, assets: list });
      } catch (err) {
        console.error("get assets err:", err);
        res.status(500).json({ error: "Failed to load assets" });
      }
    });

    // HR only: add asset
    app.post("/assets", verifyToken, verifyHR, async (req, res) => {
      try {
        const asset = req.body;
        asset.dateAdded = new Date();

        const result = await assets.insertOne(asset);

        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.log("Add Asset Error:", err);
        res.status(400).json({ error: "Failed to add asset" });
      }
    });

    app.put("/assets/:id", verifyToken, verifyHR, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;

        // ensure numeric fields
        if (updatedData.productQuantity !== undefined)
          updatedData.productQuantity = Number(updatedData.productQuantity);
        if (updatedData.availableQuantity !== undefined)
          updatedData.availableQuantity = Number(updatedData.availableQuantity);

        // prevent overwriting dateAdded accidentally
        delete updatedData.dateAdded;

        const result = await assets.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .json({ success: false, error: "Asset not found" });
        }

        res.json({ success: true });
      } catch (err) {
        console.error("update asset err:", err);
        res.status(500).json({ error: "Update failed" });
      }
    });

    // HR only: delete asset
    app.delete("/assets/:id", verifyToken, verifyHR, async (req, res) => {
      try {
        const id = req.params.id;

        // Delete asset by _id only
        const result = await assets.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res
            .status(404)
            .json({ success: false, error: "Asset not found" });
        }

        res.json({ success: true });
      } catch (err) {
        console.error("delete asset err:", err);
        res.status(500).json({ error: "Delete failed" });
      }
    });

    // ------------------ REQUESTS ------------------

    // Employee: create request
    // POST /requests
    app.post("/requests", verifyToken, async (req, res) => {
      try {
        const { assetId, note } = req.body;

        const employee = req.currentUser;

        // Find HR of same company
        const hr = await users.findOne({
          role: "hr",
          companyName: employee.companyName,
        });

        const asset = await assets.findOne({ _id: new ObjectId(assetId) });
        if (!asset)
          return res
            .status(404)
            .json({ success: false, error: "Asset not found" });

        const newRequest = {
          assetId,
          assetName: asset.productName,
          assetType: asset.productType,
          requesterName: employee.name,
          requesterEmail: employee.email,
          hrEmail: hr ? hr.email : null,
          companyName: hr ? hr.companyName : null,
          requestDate: new Date(),
          requestStatus: "pending",
          note: note || "",
          processedBy: null,
        };

        await requests.insertOne(newRequest);

        res.json({ success: true, message: "Request submitted successfully" });
      } catch (err) {
        console.error("Request creation error:", err);
        res
          .status(500)
          .json({ success: false, error: "Failed to submit request" });
      }
    });

    app.get("/requests", verifyToken, async (req, res) => {
      try {
        const userEmail = req.currentUser.email;
        const myRequests = await requests
          .find({ requesterEmail: userEmail })
          .toArray();
        res.json(myRequests);
      } catch (err) {
        console.error("Fetch requests error:", err);
        res.status(500).json({ error: "Failed to load requests" });
      }
    });

    // GET /requests/my
    app.get("/requests/my", verifyToken, async (req, res) => {
      try {
        const data = await requests
          .find({ requesterEmail: req.currentUser.email })
          .toArray();
        res.json(data);
      } catch (err) {
        console.error("get my requests err:", err);
        res.status(500).json({ error: "Fetch failed" });
      }
    });

    // PUT /requests/:id
    app.put("/requests/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const { note } = req.body;

        if (!note || note.trim() === "")
          return res.status(400).json({ error: "Note cannot be empty" });

        const result = await requests.updateOne(
          { _id: new ObjectId(id) }, // remove requesterEmail filter
          { $set: { note } }
        );

        // Ignore modifiedCount 0 for unchanged note
        res.json({
          success: true,
          message: result.modifiedCount > 0 ? "Note updated" : "Note unchanged",
        });
      } catch (err) {
        console.error("Update request error:", err);
        res.status(500).json({ error: "Update failed" });
      }
    });

    // DELETE /requests/:id
    app.delete("/requests/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await requests.deleteOne({
          _id: new ObjectId(id),
          requesterEmail: req.currentUser.email,
        });

        if (result.deletedCount > 0) res.json({ success: true });
        else res.status(400).json({ error: "Delete failed" });
      } catch (err) {
        console.error("delete request err:", err);
        res.status(500).json({ error: "Delete failed" });
      }
    });

    // HR: get all requests for their company
    // GET /requests/hr
    // HR: fetch all requests
    app.get("/requests/hr", verifyToken, verifyHR, async (req, res) => {
      try {
        // Fetch all requests, no company filter
        const data = await requests.find({}).toArray();
        res.json(data);
      } catch (err) {
        console.error("HR requests fetch error:", err);
        res.status(500).json({ error: "Fetch requests failed" });
      }
    });

    // HR: update request status

    app.patch(
      "/requests/:id/:action",
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          const { id, action } = req.params; // action = approve / reject
          const status = action === "approve" ? "approved" : "rejected";

          const update = {
            requestStatus: status,
            approvalDate: new Date(),
            processedBy: req.currentUser.name,
            hrEmail: req.currentUser.email,
          };

          const result = await requests.updateOne(
            { _id: new ObjectId(id) },
            { $set: update }
          );

          res.json({ success: result.modifiedCount > 0 });
        } catch (err) {
          console.error(err);
          res.status(500).json({ error: "Update failed" });
        }
      }
    );

    
    // HR: reject request
    // POST /requests/:id/reject
    app.post(
      "/requests/:id/reject",
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          const id = req.params.id;
          const reqDoc = await requests.findOne({ _id: new ObjectId(id) });
          if (!reqDoc)
            return res.status(404).json({ error: "Request not found" });
          if (reqDoc.requestStatus !== "pending")
            return res.status(400).json({ error: "Request not pending" });

          await requests.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                requestStatus: "rejected",
                approvalDate: new Date(),
                processedBy: req.currentUser.email,
              },
            }
          );

          res.json({ success: true, message: "Request rejected" });
        } catch (err) {
          console.error("reject err:", err);
          res.status(500).json({ error: "Reject failed" });
        }
      }
    );

    // ------------------ RETURN ASSET (Employee) ------------------
    // -----------------------------
    // GET assigned assets for logged-in user
    // -----------------------------
    app.get("/assignedAssets", verifyToken, async (req, res) => {
      try {
        const userEmail = req.currentUser.email;

        const assigned = await assignedAssets
          .find({ employeeEmail: userEmail })
          .toArray();

        res.json({ assignedAssets: assigned });
      } catch (err) {
        console.error("Fetch assigned assets error:", err);
        res.status(500).json({ error: "Failed to fetch assigned assets" });
      }
    });

    // -----------------------------
    // RETURN assigned asset
    // -----------------------------
    app.post("/assigned/:id/return", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;

        const assignment = await assignedAssets.findOne({
          _id: new ObjectId(id),
        });

        if (!assignment)
          return res.status(404).json({ error: "Assigned asset not found" });

        if (assignment.employeeEmail !== req.currentUser.email)
          return res.status(403).json({ error: "Not your assigned asset" });

        if (assignment.status === "returned")
          return res.status(400).json({ error: "Already returned" });

        // Mark as returned
        await assignedAssets.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "returned", returnDate: new Date() } }
        );

        // Increase available quantity if returnable
        const assetDoc = await assets.findOne({
          productName: assignment.assetName,
          hrEmail: assignment.hrEmail,
        });

        if (assetDoc && assignment.assetType === "Returnable") {
          await assets.updateOne(
            { _id: assetDoc._id },
            { $inc: { availableQuantity: 1 } }
          );
        }

        // Update requests collection status if exists
        await requests.updateOne(
          {
            assetId: assignment.assetId,
            requesterEmail: assignment.employeeEmail,
            requestStatus: "approved",
          },
          { $set: { requestStatus: "returned", approvalDate: new Date() } }
        );

        res.json({ success: true, message: "Asset returned successfully" });
      } catch (err) {
        console.error("Return error:", err);
        res.status(500).json({ error: "Return failed" });
      }
    });

    // ------------------ AFFILIATIONS & EMPLOYEE LIST ------------------
    // HR: list employees affiliated to this HR
    app.get("/hr/employees", verifyToken, verifyHR, async (req, res) => {
      try {
        console.log("✅ HR current user:", req.currentUser);
        const hrEmail = req.currentUser.email;

        // find active employee affiliations
        const links = await affiliations
          .find({ hrEmail, status: "active" })
          .toArray();
        console.log("📌 Affiliations found:", links);

        if (!links || links.length === 0) return res.json({ employees: [] });

        const employeeEmails = links.map((l) => l.employeeEmail);
        console.log("📌 Employee Emails:", employeeEmails);

        // fetch employee user details
        const employeeDetails = await users
          .find({ email: { $in: employeeEmails } })
          .project({ password: 0 })
          .toArray();
        console.log("📌 Employee Details:", employeeDetails);

        const finalResult = employeeDetails.map((u) => {
          const link = links.find((l) => l.employeeEmail === u.email);
          return {
            employeeName: u.name,
            employeeEmail: u.email,
            photo: u.profileImage || "",
            joinDate: u.createdAt,
            assignedAssets: u.assignedAssets || 0,
            status: link.status,
          };
        });

        res.json({ employees: finalResult });
      } catch (err) {
        console.error("hr employees err:", err);
        res.status(500).json({ error: "Fetch failed" });
      }
    });

    // Auto-affiliate employee when HR approves asset request
    app.patch(
      "/requests/:id/approve",
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          const { id } = req.params;

          const requestDoc = await requests.findOne({ _id: new ObjectId(id) });
          if (!requestDoc)
            return res.status(404).json({ error: "Request not found" });
          if (requestDoc.requestStatus !== "pending")
            return res.status(400).json({ error: "Request not pending" });

          const hr = req.currentUser;

          // Check HR package limit
          if (hr.currentEmployees >= hr.packageLimit) {
            return res
              .status(400)
              .json({ error: "Cannot approve: HR employee limit reached" });
          }

          // Update request status
          await requests.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                requestStatus: "approved",
                approvalDate: new Date(),
                processedBy: hr.name,
                hrEmail: hr.email,
              },
            }
          );

          // Check if employee already affiliated
          const existingAff = await affiliations.findOne({
            employeeEmail: requestDoc.requesterEmail,
            hrEmail: hr.email,
            status: "active",
          });

          if (!existingAff) {
            // create new affiliation
            await affiliations.insertOne({
              employeeEmail: requestDoc.requesterEmail,
              hrEmail: hr.email,
              companyName: hr.companyName,
              status: "active",
              joinedAt: new Date(),
            });

            // increment HR currentEmployees
            await users.updateOne(
              { email: hr.email },
              { $inc: { currentEmployees: 1 } }
            );
          }

          res.json({
            success: true,
            message: "Request approved and affiliation done",
          });
        } catch (err) {
          console.error("Approve request error:", err);
          res.status(500).json({ error: "Approval failed" });
        }
      }
    );

    // HR: remove affiliation (remove from team)
    app.delete(
      "/hr/employees/:email",
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          const empEmail = req.params.email;

          const aff = await affiliations.findOne({
            employeeEmail: empEmail,
            hrEmail: req.currentUser.email,
            status: "active",
          });
          if (!aff)
            return res.status(404).json({ error: "Affiliation not found" });

          // mark affiliation inactive
          await affiliations.updateOne(
            { _id: aff._id },
            { $set: { status: "inactive" } }
          );

          // decrement currentEmployees
          await users.updateOne(
            { email: req.currentUser.email },
            { $inc: { currentEmployees: -1 } }
          );

          res.json({ success: true });
        } catch (err) {
          console.error("remove employee err:", err);
          res.status(500).json({ error: "Remove failed" });
        }
      }
    );

    // ------------------ PAYMENTS (Stripe checkout session) ------------------
    // Create checkout session for package upgrade (requires stripe env)
    // ------------------
    // GET all packages
    // -----------------------------
    app.get("/packages", async (req, res) => {
      try {
        const allPackages = await packages.find({}).toArray();
        res.json({ packages: allPackages });
      } catch (err) {
        console.error("Fetch packages error:", err);
        res.status(500).json({ error: "Failed to fetch packages" });
      }
    });

    // -----------------------------
    // GET all packages
    // -----------------------------
    app.get("/packages", verifyToken, async (req, res) => {
      try {
        const allPackages = await packages.find({}).toArray();
        res.json({ packages: allPackages });
      } catch (err) {
        console.error("Fetch packages error:", err);
        res.status(500).json({ error: "Failed to fetch packages" });
      }
    });

    // -----------------------------
    // GET all payments for logged-in HR
    // -----------------------------
    app.get("/payments", verifyToken, async (req, res) => {
      try {
        const hrEmail = req.currentUser.email;
        const allPayments = await payments.find({ hrEmail }).toArray();
        res.json({ payments: allPayments });
      } catch (err) {
        console.error("Fetch payments error:", err);
        res.status(500).json({ error: "Failed to fetch payments" });
      }
    });

    // -----------------------------
    // CREATE STRIPE CHECKOUT SESSION
    // -----------------------------
    app.post(
      "/create-checkout-session",
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          // Check if Stripe is configured
          if (!stripe) {
            return res.status(500).json({
              error: "Stripe is not configured. Set STRIPE_SECRET_KEY in .env",
            });
          }

          const { packageId } = req.body;
          if (!packageId)
            return res.status(400).json({ error: "packageId required" });

          const pkg = await packages.findOne({ _id: new ObjectId(packageId) });
          if (!pkg) return res.status(404).json({ error: "Package not found" });

          const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [
              {
                price_data: {
                  currency: "usd",
                  product_data: { name: pkg.name + " Package" },
                  unit_amount: Math.round(pkg.price * 100),
                },
                quantity: 1,
              },
            ],
            mode: "payment",
            success_url: `${
              process.env.CLIENT_URL || "http://localhost:5173"
            }/payment-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${
              process.env.CLIENT_URL || "http://localhost:5173"
            }/payment-cancel`,
            metadata: {
              hrEmail: req.currentUser.email,
              packageId: packageId.toString(),
            },
          });

          res.json({ url: session.url });
        } catch (err) {
          console.error("create checkout err:", err);
          res.status(500).json({ error: "Failed to create checkout session" });
        }
      }
    );

    // ----------------- Start server -----------------
    app.listen(port, () => {
      console.log(`🚀 Server running on PORT ${port}`);
    });
  } catch (err) {
    console.error("❌ Server failed:", err);
  }

  // await client.db("admin").command({ping: 1});
  // console.log("ping your deployment , you succesfully conected to mongo")
}

// Run server
runServer();
