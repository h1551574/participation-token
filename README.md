# Participation Token (via Flask + LTI 1.3 Advantage)
## Description
Participation token is an web-tool which, once setup, greatly reduces the administrative the process of handing out in-class participation points. It was built with ease of use and security in mind.

## Deployment Guide
In this guide we will go through the steps required to install the project on a new Ubuntu Machine and how to run some small user tests.
**Important: This tutorial assumes you have an Ubuntu Machine with Version 20.04.3 already setup!**
### Setup:
- Clone this Repository to your local environment
- Create a pip virtual environment and install dependencies
- Initialize Database
- Configure Flask Application
- Start Flask Application
- Start Celery Worker (incl. celery beat)

#### Clone Repository
First create a new project folder and navigate to it. Then clone the repository to your local environment (Make sure to install git on your machine):
```sh
git clone https://github.com/h1551574/participation-token.git
```
#### Create a pip virtual environment and install dependencies
Now navigate to participation-tokenn:
```sh
cd participation-token
```
Now install pip:
```sh
sudo apt install python3-pip
```

Inside this folder follow [this tutorial](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/
) for creating and activating a pip virtual environment.

Continue with the next steps inside your virtual environment!

Now, install the necessary requirements from the requirements text file (Note: this process can produce some "Error" warnings, which are, however, automatically resolved):

```sh
sudo pip3 install -r requirements.txt
```
(Note: Install as with root user sudo since else running other scripts with root user will not have access to the modules installed in this step)
#### Initialize Database
Now navigate to the application folder, create athe databases folder and execute the init_db script to initialize the sqlite3 database:
```sh
cd participation-token
mkdir databases
sudo python3 init_db.py
```
#### Configure Flask Application
With the project configuration folder participation-token/configs you will find the following example configurations for the application:

- example_issuer_config.json
- example_private.key
- example_public.key

Please modify the issuer config to match your target platform and supply your own private and public key for the LTI OAuth authentification. The app will expect the tree configuration files with the following name (dropping"example_"):

- issuer_config.json
- private.key
- public.key
