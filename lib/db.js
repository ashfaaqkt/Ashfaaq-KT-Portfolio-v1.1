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
      dbName: 'portfolio_db', // Ensures connection to your specific database, not 'test'
    };

    if (!process.env.MONGO_URI) {
      throw new Error('Please define the MONGO_URI environment variable inside .env');
    }

    cached.promise = mongoose.connect(process.env.MONGO_URI, opts).then((mongooseInstance) => {
      console.log('MongoDB connected (cached)');
      return mongooseInstance;
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
