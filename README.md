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

**Configure Tool Domain**: You will need to expose the tool over a public domain name for it to work. For the purposes of this tutorial we will use [ngrok](https://ngrok.com/) to expose the tool. For how to use 

After exposing port 9001 over your domain (or ngrok) modify the "TOOL_URL" entry in the configuration in line 75 of app.py.
#### Start Flask Application
Inside the application folder /participation-token/participation-token run the following script:
```sh
python3 app.py
```
The app should now run on port 9001. Now start the celery worker, which handles long running tasks.

#### Install redis for celery
Follow Step 1 of [this tutorial](https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-redis-on-ubuntu-20-04) to install redis.

#### Start Celery Worker (incl. celery beat)
Now parallel to the flask app start the corresponding celery worker (**Important:** make sure you are working in the virtual environment you have created):

Note: For the purposes of this tutorial we start the celery worker with an included celery beat instance. While this is practical this is not typical for production environments. Read [this](https://docs.celeryq.dev/en/stable/userguide/periodic-tasks.html#starting-the-scheduler) for more info.

```sh
celery -A app.celery worker -B
```

While Celery handles the long running task of generating tokens, celery beat schedules the periodic task which expires old batches of generated tokens.

Now the flask app and the celery worker (incl. beat) should be up and running and you can continue to the short tests section.
