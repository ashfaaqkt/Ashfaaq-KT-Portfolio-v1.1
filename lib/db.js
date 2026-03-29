const mongoose = require('mongoose');

/** 
 * Global is used here to maintain a cached connection across hot reloads
 * in development and across function invocations in production (Vercel).
 */
let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false, // Solid practice for serverless
    };

    cached.promise = mongoose.connect(process.env.MONGO_URI, opts).then((mongoose) => {
      console.log('MongoDB connected (cached)');
      return mongoose;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    throw e;
  }

  return cached.conn;
}

module.exports = connectDB;
