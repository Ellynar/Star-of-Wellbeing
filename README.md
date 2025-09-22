# STAR Assessment Backend

## Prerequisites
- Node.js (v18+ recommended)
- MongoDB (local or cloud instance)

## Setup

1. Clone the repository
2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following contents:
```
MONGODB_URI=mongodb://localhost:27017/star_assessment
PORT=8080
```

## Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

## Environment Variables
- `MONGODB_URI`: Connection string for MongoDB database
- `PORT`: Port on which the server will run (default: 8080)

## Features
- MongoDB integration for user data storage
- Rate limiting
- PDF generation
- Email report sending

## API Endpoints
- `/submit`: POST endpoint for saving user assessment data
- `/generate-pdf`: GET endpoint for generating PDF reports

## Troubleshooting
- Ensure MongoDB is running
- Check `.env` file for correct configuration
- Verify all dependencies are installed
