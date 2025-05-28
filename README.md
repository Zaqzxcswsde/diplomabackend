# General informaiton
## What is this?
A backend for my diploma, a two-factor authentication app ([mobile app](https://github.com/Zaqzxcswsde/diplomamobile) + [backend](https://github.com/Zaqzxcswsde/diplomabackend) + [PC admin client](https://github.com/Zaqzxcswsde/diplomaadminpanel)).\
Api specification (without comments) can be found through [this link](https://b5mfc0szys.apidog.io).
## Status
Done. Bugfixes from tests to come.

# Installation and usage
## Installation
I was experimenting with proper DevOps and CI/CD with this one, so the installation should be pretty straightforward
### As a test run
0. Install docker (if its not already installed)
   - Run `docker version` and `docker compose version` to check.\
If you get a proper output (starting with something like `Client: Docker Engine...` and `Docker Compose version...` respectively), then you already have them installed and <ins>can skip this stage</ins>\
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
   - *(optional)* `docker rmi diplomabackend-diplomabackend` (if it errors out, run `docker images`, check for the `IMAGE ID` field and insert in place of `diplomabackend-diplomabackend` in the previous command)
### On an actual production environment
God help you.\
No but actually, why would you do that?\
Anyway, check out the [deploy script](.github/workflows/deploy.yml), it has a relatively sophisticated deployment logic.\
As for the server infrastructure, I use nginx as a proxy (plus it handles https), and that's pretty much it.