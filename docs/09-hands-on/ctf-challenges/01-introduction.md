# Introduction & Setup

## Hands-On Vulnerable Lab Environment Setup
To safely practice the vulnerabilities detailed in this module, we will utilize a containerized environment powered by Docker and Docker Compose. This ensures that the vulnerable applications are isolated from your host machine and network.

### Prerequisites Installation
Ensure you have the following installed on your machine:
- Docker Engine
- Docker Compose
- Python 3.10+
- Git

### CTF Challenge Framework Architecture
The lab uses a multi-tier microservice architecture to simulate a modern application stack. The environment consists of:
- **Frontend Service**: A vulnerable React/Node.js web app.
- **Backend API Service**: A vulnerable Python FastAPI server.
- **Database Service**: A PostgreSQL database containing the "flags".
- **AI/ML Service**: An internal LLM agent service vulnerable to prompt injection.

### Docker Compose Deployment
Create a `docker-compose.yml` file to orchestrate the environment:

```yaml
version: '3.8'
services:
  vulnerable-api:
    image: my-vuln-api:latest
    build: ./api
    ports:
      - "8000:8000"
    environment:
      - DB_HOST=db
      - SECRET_KEY=supersecretkey
    depends_on:
      - db

  vulnerable-web:
    image: my-vuln-web:latest
    build: ./web
    ports:
      - "3000:3000"
    depends_on:
      - vulnerable-api

  db:
    image: postgres:14
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=vulndb
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  db_data:
```

To start the lab environment, run:
```bash
docker-compose up -d --build
```

### The Flag Format
Throughout the challenges, you will be searching for flags that prove you have successfully exploited a vulnerability. Flags will follow the format: `flag{random_hex_string}`.
