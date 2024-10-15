# Foodie Radar Service <img src="https://antonioaranda.dev/images/foodie-radar/icon.png" width="30" alt="App Icon" style="vertical-align: bottom;">

This repository contains the backend service for Foodie Radar, a web application that recommends restaurants based on cuisine preferences and location. The service is written in Go, containerized with Docker, and utilizes the Google Places API.

## Features

- User authentication (signup, login, logout)
- Restaurant recommendations based on location and cuisine preferences
- Saving and managing favorite restaurants
- Integration with Google Places API for up-to-date restaurant information

## Prerequisites

To run this project, you'll need:

- Go 1.23.0 or later
- Docker
- Google Cloud Platform account with Places API enabled
- PostgreSQL database

## Environment Variables

Make sure to set the following environment variables:

- `JWT_SECRET`: Secret key for JWT token generation
- `DATABASE_URL`: PostgreSQL connection string
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to your Google Cloud credentials file

## Getting Started

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/foodie-radar-service.git
   cd foodie-radar-service
   ```

2. Build the Docker image:
   ```
   docker build -t foodie-radar-service .
   ```

3. Run the container:
   ```
   docker run -p 8080:8080 \
     -e JWT_SECRET=your_jwt_secret \
     -e DATABASE_URL=your_database_url \
     -e GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json \
     -v /path/to/credentials.json:/path/to/credentials.json \
     foodie-radar-service
   ```

## API Endpoints

- `POST /api/signup`: Create a new user account
- `POST /api/login`: Authenticate a user and receive a JWT token
- `POST /api/logout`: Log out a user
- `POST /api/restaurants`: Get restaurant recommendations (authenticated)
- `POST /api/restaurants-no-auth`: Get restaurant recommendations (unauthenticated)
- `PUT /api/put-saved-restaurant`: Save a restaurant to user's favorites
- `DELETE /api/delete-saved-restaurant`: Remove a restaurant from user's favorites
- `GET /api/get-saved-restaurants`: Retrieve user's saved restaurants

## Development

To run the project locally for development:

1. Install dependencies:
   ```
   go get -d -v ./...
   ```

2. Run the application:
   ```
   go run main.go
   ```

## Deployment

This service is designed to be deployed on Google Cloud Run. Make sure to set the appropriate environment variables in your Cloud Run configuration.
