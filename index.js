require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const nunjucks = require("nunjucks");
const { nanoid } = require("nanoid");
const { pbkdf2Sync } = require("crypto");
const { MongoClient, ObjectId } = require("mongodb");
const marked = require("marked");
const createDomPurify = require("dompurify");
const { JSDOM } = require("jsdom");
const dompurify = createDomPurify(new JSDOM().window);
const clientPromise = MongoClient.connect(process.env.DB_URI, { maxPoolSize: 10 });
const app = express();
const LIMITARRAY = 20;

const chunk = (array, chunkSize) => {
  const size = Math.ceil(array.length / chunkSize);
  const chunks = new Array(size).fill(0);
  return chunks.map((_, index) => {
    const start = index * chunkSize;
    const end = (index + 1) * chunkSize;
    const sliced = array.slice(start, end);
    return sliced;
  });
};

const hash = (d) => pbkdf2Sync(d, "salt", 100000, 64, "sha512").toString("hex");

const getStartingMonth = (v) => {
  const d = new Date();
  const month = Number(v[0]);
  d.setDate(d.getDay() - 1);
  return d.setMonth(d.getMonth() - month);
};

const createUser = async (db, userName, password) => {
  const passwordHash = hash(password);
  return await db.collection("users").insertOne({
    userName,
    passwordHash,
  });
};

const findUserByUsername = async (db, userName) => db.collection("users").findOne({ userName });

const findUserBySessionId = async (db, sessionId) => {
  const session = await db.collection("sessions").findOne(
    { sessionId },
    {
      projection: { userId: 1 },
    }
  );

  if (!session) {
    return;
  }

  return db.collection("users").findOne({ _id: session.userId });
};

const createSession = async (db, userId) => {
  const sessionId = nanoid();

  await db.collection("sessions").insertOne({
    userId,
    sessionId,
  });

  return sessionId;
};

const deleteSesion = async (db, sessionId) => {
  await db.collection("sessions").deleteOne({ sessionId });
};

const createNote = async (db, table, data) => {
  return await db.collection(table).insertOne(data);
};

const findNote = async (db, table, noteId) => {
  return await db.collection(table).findOne({ _id: noteId });
};

const findNoteCustomId = async (db, table, id) => {
  return await db.collection(table).findOne({ _id: id });
};

const findNotesByUserId = async (db, tableName, userId, isArchived, age) =>
  await db
    .collection(tableName)
    .find({ userId: userId, isArchived: isArchived, created: { $gt: new Date(age) } })
    .sort({ created: -1 })
    .toArray();

const updateNote = async (db, id, data) => {
  return await db.collection("notes").updateOne({ _id: id }, { $set: data });
};

const deleteNote = async (db, table, id) => {
  await db.collection(table).deleteOne({ _id: id });
};

const deleteNoteAll = async (db, table, userId) => {
  await db.collection(table).deleteMany({ userId: userId, isArchived: true });
};

nunjucks.configure("views", {
  autoescape: true,
  express: app,
});

app.set("view engine", "njk");
app.use(express.json());
app.use(express.static("public"));
app.use(cookieParser());

app.use(async (req, res, next) => {
  try {
    const client = await clientPromise;
    req.db = client.db("users");
    next();
  } catch (err) {
    next(err);
  }
});

const auth = () => async (req, res, next) => {
  if (!req.cookies["sessionId"]) {
    return next();
  }
  const user = await findUserBySessionId(req.db, req.cookies["sessionId"]);
  req.user = user;
  req.sessionId = req.cookies["sessionId"];
  next();
};

app.get("/", auth(), (req, res) => {
  if (req.user) {
    res.redirect("/dashboard");
  } else {
    res.render("index", {
      authError: req.query.authError,
    });
  }
});

app.get("/dashboard", auth(), (req, res) => {
  if (!req.user) {
    return res.redirect("/");
  }

  res.render("dashboard", {
    user: req.user,
  });
});

app.post("/login", bodyParser.urlencoded({ extended: false }), async (req, res) => {
  const { username, password } = req.body;
  const user = await findUserByUsername(req.db, username);

  if (!user) {
    return res.redirect("/?authError=Unknown%20username");
  }
  if (user.passwordHash !== hash(password)) {
    return res.redirect("/?authError=Wrong%20password");
  }

  const sessionId = await createSession(req.db, user._id);
  res.cookie("sessionId", sessionId, { httpOnly: true }).redirect("/");
});

app.post("/signup", bodyParser.urlencoded({ extended: false }), async (req, res) => {
  const { username, password } = req.body;
  const user = await findUserByUsername(req.db, username);
  if (user) {
    return res.redirect("/?authError=The%20user%20is%20already%20registered");
  }
  const newUserId = await createUser(req.db, username, password);
  const sessionId = await createSession(req.db, newUserId.insertedId);
  res.cookie("sessionId", sessionId, { httpOnly: true }).redirect("/");
});

app.get("/logout", auth(), async (req, res) => {
  if (!req.user) {
    return res.redirect("/");
  }
  await deleteSesion(req.db, req.sessionId);
  res.clearCookie("sessionId").redirect("/");
});

app.get("/api/notes", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }

  let array = [];
  let archive = false;
  let age = "1970-01-01";
  let hasMore = false;

  if (req.query.age === "archive") {
    archive = true;
  }

  if (req.query.age === "1month" || req.query.age === "3months") {
    age = getStartingMonth(req.query.age);
  }

  array = await findNotesByUserId(req.db, "notes", req.user._id, archive, age);

  if (array.length > LIMITARRAY) {
    const test = chunk(array, LIMITARRAY);
    array = test[Number(req.query.page) - 1];
    if (test.length > req.query.page) {
      hasMore = true;
    }
  }

  res.json({ data: array, hasMore: hasMore });
});

app.get("/api/note/:id", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }

  const id = req.params.id;
  const note = await findNoteCustomId(req.db, "notes", new ObjectId(id));
  res.json(note);
});

app.post("/api/notes", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }

  const note = {
    created: new Date(),
    title: req.body.title,
    text: req.body.text,
    userId: req.user._id,
    isArchived: false,
    html: dompurify.sanitize(marked(req.body.text)),
  };

  await createNote(req.db, "notes", note)
    .then(async (result) => {
      const timer = await findNote(req.db, "notes", result.insertedId);
      res.json({ _id: timer._id.toString() });
    })
    .catch((err) => {
      console.error(err);
      return res.json({ success: false, message: "An error occurred, please try again later." });
    });
});

app.post("/api/note/:id/edit", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }
  const id = req.params.id;

  const data = {
    title: req.body.title,
    text: req.body.text,
    html: dompurify.sanitize(marked(req.body.text)),
  };

  try {
    const { modifiedCount } = await updateNote(req.db, new ObjectId(id), data);

    if (modifiedCount === 0) {
      res.status(404).send(`Unknown user Id: ${id}`);
    } else {
      res.json({ _id: id });
    }
  } catch (err) {
    res.send(err.message);
  }
});

app.post("/api/note/:id/archive", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }
  const id = req.params.id;

  const data = {
    isArchived: req.body.isArchived,
  };

  try {
    const { modifiedCount } = await updateNote(req.db, new ObjectId(id), data);

    if (modifiedCount === 0) {
      res.status(404).send(`Unknown user Id: ${id}`);
    } else {
      res.json({ _id: id });
    }
  } catch (err) {
    res.send(err.message);
  }
});

app.delete("/api/note/:id", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }

  const id = req.params.id;

  try {
    await deleteNote(req.db, "notes", new ObjectId(id));
    res.json({ _id: id });
  } catch (err) {
    res.send(err.message);
  }
});

app.delete("/api/note", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }

  try {
    deleteNoteAll(req.db, "notes", req.user._id).then();
    res.json({});
  } catch (err) {
    res.send(err.message);
  }
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`  Listening on http://localhost:${port}`);
});
