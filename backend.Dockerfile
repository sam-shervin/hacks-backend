# Use Node.js base image
FROM node:20

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

COPY prisma ./

RUN npm install -g pnpm && pnpm install

COPY prisma ./prisma

RUN pnpx prisma generate

# Copy the application code
COPY . .

# Expose the app port
EXPOSE 8032

# Command to run the app
CMD ["node", "index.js"]