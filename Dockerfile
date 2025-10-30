# Use LTS version of Node.js instead of latest
FROM node:20-slim

WORKDIR /server

# Install build dependencies for bcrypt
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Clean install dependencies and force rebuild of native modules
RUN npm install --only=production
RUN npm rebuild bcrypt --build-from-source

# Copy frontend files before building
COPY passkeys_frontend/ ./passkeys_frontend/

# Set up frontend build
WORKDIR /server/passkeys_frontend
RUN rm -rf node_modules package-lock.json || true
RUN npm install
RUN npm run build 

# Return to main directory and copy any remaining files
WORKDIR /server
COPY . .

# Remove potentially copied node_modules from host to prevent conflicts
RUN rm -rf node_modules

# Reinstall/rebuild native modules to ensure compatibility
RUN npm install --only=production
RUN npm rebuild bcrypt --build-from-source

# Expose the port
EXPOSE 3000

# Run the application
CMD ["node", "server.js"]