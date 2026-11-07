import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
 
const SALT_ROUNDS = 10;
 
// A bcrypt hash looks like $2a$10$... / $2b$10$... (60 chars). Used so we never
// hash an already-hashed value twice (e.g. if a seed script hashes by itself).
const isBcryptHash = (value) =>
  typeof value === 'string' && /^\$2[aby]\$\d{2}\$.{53}$/.test(value);
 
// Instructor Portal account.
//
// SECURITY: password, apiKey, privateEmail and privatePhone are PRIVATE.
//  - `select: false` means they are never loaded by find/findOne unless a query
//    explicitly asks for them (e.g. .select('+password') during login).
//  - The toJSON transform is a second safety net so they can never leak if a
//    document is accidentally serialized.
//  - The password is stored as a bcrypt hash, never as plain text.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, select: false },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'
 
    // Private fields (never exposed by the API).
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  {
    timestamps: true,
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
        delete ret.apiKey;
        delete ret.privateEmail;
        delete ret.privatePhone;
        return ret;
      }
    }
  }
);
 
// Hash the password whenever it is set or changed (create / save).
instructorSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  if (isBcryptHash(this.password)) return;
  this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
});
 
export const Instructor = mongoose.model('Instructor', instructorSchema);
 

