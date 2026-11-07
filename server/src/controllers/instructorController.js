import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';
 
// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  (secured)
// =============================================================================
//  Defence in depth against NoSQL injection:
//   1. express-mongo-sanitize (registered in app.js) neutralises any key that
//      starts with `$` or contains `.` in req.body / req.query / req.params.
//   2. Joi allow-lists the exact fields and forces each one to be a string, so
//      an object like {"$ne": null} (or its sanitized form) is rejected.
//   3. Passwords are bcrypt hashes and are compared with bcrypt.compare, never
//      placed inside a database query.
//   4. Search text is regex-escaped and only ever used as a plain string match.
//   5. Secret fields are never selected or returned.
// =============================================================================
 
const loginSchema = Joi.object({
  username: Joi.string().trim().max(64).required(),
  password: Joi.string().max(128).required()
}).required();
 
// Only these fields may be used to search, and only as plain strings.
const searchSchema = Joi.object({
  name: Joi.string().trim().max(64),
  department: Joi.string().trim().max(64),
  role: Joi.string().trim().max(32)
});
 
// Compared against when the username does not exist, so a missing user and a
// wrong password take about the same time (avoids user enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);
 
const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
 
// Only PUBLIC fields. apiKey, privateEmail, privatePhone and password are
// private and are never returned.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}
 
// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { error, value } = loginSchema.validate(req.body || {}, { abortEarly: true });
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
 
    // `username` is guaranteed to be a plain string here, so it can only be
    // matched literally. The password is NOT part of the query.
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');
 
    const hash = instructor ? instructor.password : DUMMY_HASH;
    const passwordOk = await bcrypt.compare(value.password, hash);
 
    if (!instructor || !passwordOk) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}
 
// GET /api/instructors
// Public directory with limited fields.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}
 
// GET /api/instructors/search?name=...&department=...&role=...
export async function searchInstructors(req, res, next) {
  try {
    const { error, value } = searchSchema.validate(req.query, { abortEarly: true });
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
 
    // Build the filter ourselves from validated strings: no client-supplied
    // object or operator can ever reach the database.
    const filter = {};
    if (value.name) filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    if (value.department) filter.department = { $regex: escapeRegex(value.department), $options: 'i' };
    if (value.role) filter.role = value.role;
 
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
 

