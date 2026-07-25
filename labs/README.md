# AppSec Atlas Labs

Hands-on security exercises. All labs run locally using Docker — no cloud account required.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Basic familiarity with the terminal
- A modern browser

## Quick Start

```bash
# Clone the repo (if you haven't already)
git clone https://github.com/appsec-atlas/appsec-atlas.git
cd appsec-atlas/labs

# Start a specific lab
cd exercises/web/sql-injection-101
docker compose up -d

# Open in browser
open http://localhost:8080

# Stop the lab when done
docker compose down
```

## Available Labs

> Labs are added as guides are completed. Check back as the Atlas grows!

### Web Security
*(Coming with the Web Application Security guide)*

### API Security
*(Coming with the API Security guide)*

### Cloud Security
*(Coming with the Cloud Security guide)*

### AI/ML Security
*(Coming with the LLM Security guide)*

## Lab Structure

Each lab contains:
```
lab-name/
├── README.md          ← Objectives, setup, walkthrough hints
├── docker-compose.yml ← Start the vulnerable environment
├── challenge/         ← The vulnerable application source
├── solution/          ← Spoiler! The solution and explanation
└── assets/            ← Screenshots, diagrams
```

## Contributing a Lab

Want to build a lab? Labs are one of the most impactful contributions you can make.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

Requirements for labs:
- Must run entirely in Docker (no external dependencies)
- Must have a clear learning objective
- Must include a solution file
- Must not require internet access to function
