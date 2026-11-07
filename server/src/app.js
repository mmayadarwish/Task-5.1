import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import mongoSanitize from 'express-mongo-sanitize';
import authRoutes from './routes/auth.js';
import reviewRoutes from './routes/reviews.js';
import userRoutes from './routes/users.js';
import instructorRoutes from './routes/instructors.js';
 
const app = express();
 
app.use(morgan('dev'));
app.use(cors({ origin: 'http://localhost:5175', credentials: false }));
app.use(express.json());
 
// NoSQL injection protection: must come AFTER express.json() (so req.body is
// parsed) and BEFORE the routes. Keys starting with `$` or containing `.` are
// replaced with `_`, so {"$ne": null} becomes {"_ne": null} and can no longer
// act as a MongoDB operator. Joi then rejects the leftover object/unknown key.
app.use(
  mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
      console.warn(`[security] Sanitized "${key}" in ${req.method} ${req.originalUrl}`);
    }
  })
);
 
app.get('/api/health', (req, res) => res.json({ ok: true }));
 
app.use('/api/auth', authRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/users', userRoutes);
app.use('/api/instructors', instructorRoutes);
 
// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});
 
// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});
 
export default app;