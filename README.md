# General informaiton
## What is this?
A backend for my diploma, a two-factor authentication app (moblie + backend + PC admin client.
## Status
It is still in development, I may or may not write a proper README (and publish the client!) once its finished.

# Installation and usage
## Installation
I was experimenting with proper DevOps and CI/CD with this one, so the installation should be pretty straightforward
### As a test run
0. Install docker (if its not already installed)
   - Run `docker version` and `docker compose version` to check.\
If you get a proper output (starting with something like `Client: Docker Engine...` and `Docker Compose version...` respectively), then you already have them install and <ins>can skip this stage</ins>\
Otherwise, run
     - `curl -fsSL https://get.docker.com | sudo sh` # to run the automatic docker + compose installation script
     - `sudo usermod -aG docker $USER` # to add current user to the *docker* group so you wouln't have to run it with sudo
     - `exit` # so the permissions would apply
1. Clone the repository
   - `git clone https://github.com/Zaqzxcswsde/diplomabackend.git`
   - `cd diplomabackend`
2. Build and run
   - `docker compose up -d` (yes, with just a single command)
3. Check that its working
   - `curl http://localhost:8000/health/` should give you `{"status":"ok"}`
4. Stop the container after experimenting
   - `docker compose down`
   - *(optional)* `docker rmi diplomabackend-diplomabackend` (if it errors out, run `docker images`, check for the `IMAGE ID` field and insert in place of `diplomabackend-diplomabackend` in the previous command
