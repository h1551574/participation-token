import datetime
from enum import unique
import functools
import json
import os
import pprint
from queue import PriorityQueue
import random
from sys import set_asyncgen_hooks

from tempfile import mkdtemp
import time
from tokenize import Token
from urllib import response
from celery import Celery
import celery
from flask import Flask, jsonify, request, render_template, send_from_directory, url_for, redirect, make_response, session
from flask_caching import Cache
from flask_debugtoolbar import DebugToolbarExtension
from pytz import timezone
import sqlalchemy
from werkzeug.exceptions import Forbidden
from pylti1p3.contrib.flask import FlaskOIDCLogin, FlaskMessageLaunch, FlaskRequest, FlaskCacheDataStorage
from pylti1p3.grade import Grade
from pylti1p3.lineitem import LineItem
from pylti1p3.tool_config import ToolConfJsonFile
from pylti1p3.registration import Registration
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import false, func
import qrcode
from fpdf import FPDF
import string
import secrets
import bcrypt

import os
import sys
import shutil

from auth import is_admin_required


class ReverseProxied(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)


app = Flask('pylti1p3-game-example', template_folder='templates', static_folder='static')
app.wsgi_app = ReverseProxied(app.wsgi_app)

def get_db_path():
    return os.path.join(app.root_path, '..', 'databases', 'test.db')

config = {
    "DEBUG": True,
    "ENV": "development",
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 600,
    "SECRET_KEY": "7d6b4176f97640d9721dbcc2",
    "SESSION_TYPE": "filesystem",
    "SESSION_FILE_DIR": mkdtemp(),
    "SESSION_COOKIE_NAME": "flask-session-id",
    "SESSION_COOKIE_HTTPONLY": False,
    "SESSION_COOKIE_SECURE": True,   # should be True in case of HTTPS usage (production)
    "SESSION_COOKIE_SAMESITE": "None",  # should be 'None' in case of HTTPS usage (production)
    "DEBUG_TB_INTERCEPT_REDIRECTS": False,
    "SQLALCHEMY_DATABASE_URI": "sqlite:///databases/test_db.sqlite",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "TOOL_URL": "https://793c-2a02-8388-3c1-bb00-62da-2606-b90c-fea0.eu.ngrok.io",
    "UPLOAD_FOLDER": "uploads",
}
app.config.from_mapping(config)
cache = Cache(app)
toolbar = DebugToolbarExtension(app)

db = SQLAlchemy(app)

class Activity_config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    max_score = db.Column(db.Float, nullable=False)
    token_score = db.Column(db.Float, nullable=False)
    redirect_url = db.Column(db.String, nullable=False)
    is_closed = db.Column(db.Boolean, nullable=False)


    def __repr__(self):
        return '<Id %r> ' % self.id + '<Max  %r> ' % self.max_score + '<TS  %r> ' % self.token_score
class Grade_token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.LargeBinary, nullable=False)
    batch_id = db.Column(db.Integer, nullable=False)
    activity_id = db.Column(db.Integer, nullable=False)
    redeemed = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<Id %r> ' % self.id + '<Code  %r> ' % self.code + '<B_ID  %r> ' % self.batch_id + '<A_ID  %r> ' % self.activity_id

class Token_batch(db.Model):
    batch_id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, primary_key=True)
    expired_by = db.Column(db.DateTime, nullable=False)
    expired = db.Column(db.Boolean, nullable=False)


    def __repr__(self):
        return '<B_ID  %r> ' % self.batch_id + '<A_ID  %r> ' % self.activity_id + '<EXP_DATE  %r> ' % self.expired_by



def make_celery(app):
    celery = Celery('app')
    celery.conf.update(app.config["CELERY_CONFIG"])

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

app.config.update(CELERY_CONFIG={
    'broker_url': 'redis://localhost:6379',
    'result_backend': 'redis://localhost:6379',
})
celery = make_celery(app)

@celery.task(bind=True)
def generate_tokens_async(self,activity_url,activity_id, batch_id,amount_tokens,expired_by_date):
    tokens = []
    # Deserialize expired_by_date since Celery automatically serializes
    # data sent between Main Task and Workers into strings.
    expired_by_date = datetime.datetime.strptime(expired_by_date, '%Y-%m-%dT%H:%M:%S.%f')
    print(type(expired_by_date))
    x = range(amount_tokens)
    for n in x:
        token = secrets.token_urlsafe(nbytes=12)
        #code = token.encode('UTF-8')
        code = bcrypt.hashpw(token.encode('UTF-8'), bcrypt.gensalt(14))
        grade_token = Grade_token(code=code,batch_id=batch_id,activity_id=activity_id,redeemed=False)
        db.session.add(grade_token)
        db.session.flush()
        #print(grade_token.id)
        tokens.append([token,grade_token.id])
        self.update_state(state='PROGRESS',
                        meta={'current': n, 'total': amount_tokens,
                            'status': " of tokens generated!"})
    token_batch = Token_batch(batch_id=batch_id,activity_id=activity_id,expired_by=expired_by_date,expired=False)
    db.session.add(token_batch)
    db.session.commit()
    filename = pdf_factory_async(self,tokens,activity_url, batch_id,activity_id)

    return {'current': 100, 'total': 100, 'status': 'Task completed!',
            'result': filename}
    #return tokens

def pdf_factory_async(task,tokens,redirect_url,batch_id,activity_id):
    load_token_url = []
    app.config['TOOL_URL']
    amount_tokens = len(tokens)
    activity_id = str(activity_id)
    print(redirect_url)
    for token in tokens:
        load_token_url.append([app.config['TOOL_URL']+'/load_token/?token='+str(token[0])+'&batch_id='+str(batch_id)+'&token_id='+str(token[1])+'&redirect_url='+redirect_url,token[0]])

    class PDF(FPDF):
        def header(self):
            # Logo
            # Arial bold 15
            self.set_font('Arial', 'B', 15)
            # Move to the right
            self.cell(10)
            # Title
            self.cell(170, 10, 'Course Title: LTI | Activity:'+ str(activity_id) + ' | Batch:'+ str(batch_id), 1, 0, 'C')
            # Line break
            self.ln(20)

    pdf = PDF()
    pdf.add_page()

    pdf.set_font('Times', '', 9)
    yoffset = 21
    xoffsetRight = 155
    xoffsetMiddle = 95
    xoffsetLeft = 35
    imagePosition = 0
    imageSize = 30
    yoffset_increment = 35
    text_y_offset = 5.5
    cell_width = 62
    cell_height = 10

    pdf.ln(16) # Top Offset

    y_dash = 55
    x1_dash = 0
    x2_dash = 210

    y1_hdash = 25
    y2_hdash = 285
    x_hdash_l = 75
    x_hdash_r = 140
    progress=0
    dir = activity_id
    if not os.path.exists(dir):
        os.mkdir(dir)

    for token in load_token_url:
        qr_img = qrcode.make(token[0])
        qr_img.save(activity_id+"/qr_code_"+activity_id+token[1]+".png")
        if imagePosition==0:  
            pdf.image(activity_id+"/qr_code_"+activity_id+token[1]+".png", xoffsetLeft, yoffset, imageSize)
            pdf.cell(6,5)
            pdf.cell(cell_width, cell_height, 'Code: '+token[1], 0, 0, 'C')
            imagePosition=1
        elif imagePosition==1:
            pdf.image(activity_id+"/qr_code_"+activity_id+token[1]+".png", xoffsetMiddle, yoffset, imageSize)
            pdf.cell(cell_width, cell_height, 'Code: '+token[1], 0, 0, 'C')
            imagePosition=2
        else:
            pdf.image(activity_id+"/qr_code_"+activity_id+token[1]+".png", xoffsetRight, yoffset, imageSize)
            pdf.cell(cell_width, cell_height, 'Code: '+token[1], 0, 0, 'C')
            pdf.ln(imageSize+text_y_offset)
            imagePosition=0
            pdf.dashed_line(x1_dash, y_dash, x2_dash, y_dash, 1, 2)
            pdf.dashed_line(x_hdash_l, y1_hdash, x_hdash_l, y2_hdash, 1, 2)
            pdf.dashed_line(x_hdash_r, y1_hdash, x_hdash_r, y2_hdash, 1, 2)


            y_dash +=yoffset_increment+0.4
            yoffset += yoffset_increment+0.4
        progress += 1
        task.update_state(state='PROGRESS',
                          meta={'current': progress, 'total': amount_tokens,
                                'status': " of tokens exported to PDF!"})
        
    dir = activity_id

    try:
        shutil.rmtree(dir)
    except OSError as e:
        print("Error: %s - %s." % (e.filename, e.strerror))
    filename = make_token_batch_file_name(activity_id,batch_id)
    #filename = 'b_'+str(batch_id)+'a_'+str(activity_id)+'.pdf'
    filepath = make_token_batch_file_path(filename)
    pdf.output(filepath, 'F')
    return filename

def make_token_batch_file_name(activity_id, batch_id):
    return 'b_'+str(batch_id)+'a_'+str(activity_id)+'.pdf'

def make_token_batch_file_path(filename):
    return os.path.join(app.root_path, app.config['UPLOAD_FOLDER'],filename)

@celery.task()
def clean_up_batch_folder(activity_id, batch_id):
    filename = make_token_batch_file_name(activity_id, batch_id)
    filepath = make_token_batch_file_path(filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    else:
        print("The file '" + filename + "' does not exist, so it was not removed!")
    return


@app.route('/longtask', methods=['POST'])
@is_admin_required
def longtask():
    activity_id = session['activity_id']

    amount_tokens = int(request.form['num_tokens'])
    days_until_expired = int(request.form['days_until_expired'])

    expired_by_date = datetime.datetime.now() + datetime.timedelta(days=days_until_expired)
    print("longtask")
    print(type(expired_by_date))
    max_batch_id = db.session.query(func.max(Token_batch.batch_id)).\
    filter(Token_batch.activity_id == activity_id).\
    scalar()

    # The query returns a tuple of size 1 therefore we need element 0 
    activity_url = str(db.session.query(Activity_config.redirect_url).\
        filter(Activity_config.id == activity_id).first()[0])
    if max_batch_id:
        max_batch_id += 1
    else:
        max_batch_id = 1

    task = generate_tokens_async.apply_async((activity_url,activity_id,max_batch_id,amount_tokens,expired_by_date))
    clean_up_delay_minutes = 2
    clean_up_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=clean_up_delay_minutes)
    clean_up_batch_folder.apply_async((activity_id,max_batch_id), eta=clean_up_time)
    #task = long_task.apply_async()
    return jsonify({}), 202, {'Location': url_for('taskstatus',
                                                  task_id=task.id), 'Clean_up_delay_minutes': clean_up_delay_minutes}

@app.route('/status/<task_id>')
def taskstatus(task_id):
    task =generate_tokens_async.AsyncResult(task_id)
    #task = long_task.AsyncResult(task_id)
    if task.state == 'PENDING':
        # job did not start yet
        response = {
            'state': task.state,
            'current': 0,
            'total': 1,
            'status': 'Pending...'
        }
    elif task.state != 'FAILURE':
        response = {
            'state': task.state,
            'current': task.info.get('current', 0),
            'total': task.info.get('total', 1),
            'status': task.info.get('status', '')
        }
        if 'result' in task.info:
            response['result'] = task.info['result']
    else:
        # something went wrong in the background job
        response = {
            'state': task.state,
            'current': 1,
            'total': 1,
            'status': str(task.info),  # this is the exception raised
        }
    return jsonify(response)


# Periodic Task (every 1h) to check if any token batches are expired
@celery.task()
def check_expired_batches():
    now = datetime.datetime.now()
    print("check expired:")
    expired_batches = db.session.query(Token_batch).\
        filter(Token_batch.expired == False).\
        filter(Token_batch.expired_by < now).all()
    for batch in expired_batches:
        batch.expired = True
        # Delete all tokens of expired batch
        db.session.query(Grade_token).\
        filter(Grade_token.activity_id == batch.activity_id).\
        filter(Grade_token.batch_id == batch.batch_id).delete()
    
    db.session.commit()
    print("check expired (END)")
    return

@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Expire Batches past expire by date every hour!
    sender.add_periodic_task(datetime.timedelta(hours=1), check_expired_batches.s(), name='Checking expired batches')
    # (Every Minute for debugging purposes!)
    # sender.add_periodic_task(datetime.timedelta(minutes=1), check_expired_batches.s(), name='Checking expired batches')

# LTI Setup
PAGE_TITLE = 'Grade Token Example'


class ExtendedFlaskMessageLaunch(FlaskMessageLaunch):

    def validate_nonce(self):
        """
        Probably it is bug on "https://lti-ri.imsglobal.org":
        site passes invalid "nonce" value during deep links launch.
        Because of this in case of iss == http://imsglobal.org just skip nonce validation.

        """
        iss = self.get_iss()
        deep_link_launch = self.is_deep_link_launch()
        if iss == "http://imsglobal.org" and deep_link_launch:
            return self
        return super(ExtendedFlaskMessageLaunch, self).validate_nonce()


def get_lti_config_path():
    return os.path.join(app.root_path, '..', 'configs', 'issuer_config.json')


def get_launch_data_storage():
    return FlaskCacheDataStorage(cache)


def get_jwk_from_public_key(key_name):
    key_path = os.path.join(app.root_path, '..', 'configs', key_name)
    f = open(key_path, 'r')
    key_content = f.read()
    jwk = Registration.get_jwk(key_content)
    f.close()
    return jwk


# LTI Login Page
@app.route('/login/', methods=['GET', 'POST'])
def login():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    launch_data_storage = get_launch_data_storage()

    flask_request = FlaskRequest()
    target_link_uri = flask_request.get_param('target_link_uri')
    if not target_link_uri:
        raise Exception('Missing "target_link_uri" param')

    oidc_login = FlaskOIDCLogin(flask_request, tool_conf, launch_data_storage=launch_data_storage)
    return oidc_login\
        .enable_check_cookies()\
        .redirect(target_link_uri)


# LTI Launch Page: Learning Platform intitiates launch
# with a Post Requests which includes the necessary launch data (roles, activity_id, grade_service)
# in the request header.
@app.route('/launch/', methods=['POST', 'GET'])
def launch():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    flask_request = FlaskRequest()
    launch_data_storage = get_launch_data_storage()
    message_launch = ExtendedFlaskMessageLaunch(flask_request, tool_conf, launch_data_storage=launch_data_storage)
    message_launch_data = message_launch.get_launch_data()
    activity_id = message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/resource_link')\
        .get('id')
    session['activity_id'] = activity_id
    session.permanent = True

    
    # assigning admin rights based on lti roles
    admin_roles = [
        'http://purl.imsglobal.org/vocab/lis/v2/person#Administrator',
        'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'
    ]
    user_is_admin = False
    curr_roles = message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/roles', {})
    if any(x in admin_roles for x in curr_roles):
        user_is_admin = True

    session['is_admin'] = user_is_admin

    tpl_kwargs = {
        'page_title': PAGE_TITLE,
        'launch_data': message_launch.get_launch_data(),
        'launch_id': message_launch.get_launch_id(),
        'curr_user_name': message_launch_data.get('name', ''),
        'curr_user_name': message_launch_data.get('name', '')
    }
    
    curr_activity_id = activity_id

    activity_config = Activity_config.query.filter_by(id=curr_activity_id).first()
    tpl_kwargs['curr_activity_id'] = curr_activity_id


    


    if user_is_admin:
        if activity_config is None:
            return render_template('configure_activity.html', **tpl_kwargs)
        
        tpl_kwargs['curr_max_score'] = activity_config.max_score
        tpl_kwargs['curr_token_score'] = activity_config.token_score
        tpl_kwargs['curr_activity_url'] = activity_config.redirect_url
        

        batches = Token_batch.query.filter_by(activity_id=activity_id).all()
        tpl_kwargs['curr_batches'] = batches
        if activity_config.is_closed:
            return render_template('activity_closed.html', **tpl_kwargs)
        return render_template('manage_activity.html', **tpl_kwargs)
    if activity_config.is_closed:
        return render_template('activity_closed_student.html', **tpl_kwargs)

    # Loading in the Token that was previously set via QR Code Link

    token = session.get('token')
    token_id = session.get('token_id')
    token_batch_id = session.get('token_batch_id')
    token_batch = Token_batch.query.filter_by(batch_id=token_batch_id,activity_id=activity_id).first()
    has_max_score = False

    if token_batch is None:
        return render_template('batch_expired_removed.html')
    elif token_batch.expired:
        return render_template('batch_expired_removed.html')
    
    if token:
        print(token)
        has_token = True

        grade_token = Grade_token.query.filter_by(id=token_id,activity_id=activity_id).first()
        
        activity_config = Activity_config.query.filter_by(id=activity_id).first()
        token_redeemed = grade_token.redeemed
        # Testing 
        token_ok = bcrypt.checkpw(token.encode('UTF-8'), grade_token.code)
        if token_ok and not grade_token.redeemed:
            if not message_launch.has_ags():
                raise Forbidden("Don't have grades!")
            grades = message_launch.get_ags()

            sub = message_launch.get_launch_data().get('sub')
            timestamp = datetime.datetime.utcnow().isoformat() + 'Z'

            achieved_grade = 0

            score_line_item = LineItem()
            score_line_item.set_tag('grade_('+str(activity_id)+')') \
                .set_score_maximum(activity_config.max_score) \
                .set_label('Grade_('+str(activity_id)+')')
            if activity_id:
                score_line_item.set_resource_id(activity_id)

            scores = grades.get_grades(score_line_item)
            for sc in scores:
                if sc['userId'] == sub:
                    print('RESULT SCORE')
                    print(sc['resultScore'])
                    achieved_grade = sc['resultScore']
            
            print("achieved_grade")
            print(achieved_grade)
            if achieved_grade < activity_config.max_score:
                achieved_grade = achieved_grade+activity_config.token_score
            if achieved_grade >= activity_config.max_score:
                achieved_grade = activity_config.max_score
                has_max_score = True

            sc = Grade()
            sc.set_score_given(achieved_grade) \
                .set_score_maximum(activity_config.max_score) \
                .set_timestamp(timestamp) \
                .set_activity_progress('Completed') \
                .set_grading_progress('FullyGraded') \
                .set_user_id(sub)

            sc_line_item = LineItem()
            sc_line_item.set_tag('grade_('+str(activity_id)+')') \
                .set_score_maximum(activity_config.max_score) \
                .set_label('Grade_('+str(activity_id)+')')
            if activity_id:
                sc_line_item.set_resource_id(activity_id)

            grades.put_grade(sc, sc_line_item)
            grade_token.redeemed = True
            db.session.commit()
    else:
        has_token = False
    tpl_kwargs['curr_token'] = token
    tpl_kwargs['has_token'] = has_token
    tpl_kwargs['has_max_score'] = has_max_score
    tpl_kwargs['token_redeemed'] = token_redeemed
    return render_template('redeem_token.html', **tpl_kwargs)


@app.route('/jwks/', methods=['GET'])
def get_jwks():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    # To address Moodle Error
    return jsonify(tool_conf.get_jwks())
    # return jsonify({'keys': tool_conf.get_jwks()})


@app.route('/configure_activity/', methods=['POST'])
@is_admin_required
def configure_activity():
    if request.method == 'POST':
        activity_id = session.get('activity_id')
        max_score = request.form['max_score']
        token_score = request.form['token_score']
        redirect_url = request.form['activity_url']
        activity_config= Activity_config.query.filter_by(id=activity_id).first()
        if activity_config:
            activity_config.max_score = max_score
            activity_config.token_score = token_score
            activity_config.redirect_url = redirect_url
        else:
            activity_config = Activity_config(id=activity_id, max_score=max_score, token_score=token_score, redirect_url=redirect_url, is_closed = False)
            db.session.add(activity_config)
        db.session.commit()
        return render_template("activity_updated.html")
    return "Method Not Allowed", 403

@app.route('/close_activity/', methods=['POST'])
@is_admin_required
def close_activity():
    if request.method == 'POST':
        activity_id = session.get('activity_id')
        Token_batch.query.filter_by(activity_id=activity_id).delete()
        Grade_token.query.filter_by(activity_id=activity_id).delete()
        activity_config= Activity_config.query.filter_by(id=activity_id).first()
        activity_config.is_closed = True
        db.session.commit()
        return render_template("activity_closed.html")
    return "Method Not Allowed", 403

@app.route('/expire_batch/', methods=['POST'])
@is_admin_required
def expire_batch():
    if request.method == 'POST':
        activity_id = session.get('activity_id')
        batch_id = request.form['batch_id']
        expired_batch = Token_batch.query.filter_by(activity_id=activity_id,batch_id=batch_id).first()
        expired_batch.expired = True
        db.session.query(Grade_token).\
        filter(Grade_token.activity_id == expired_batch.activity_id).\
        filter(Grade_token.batch_id == expired_batch.batch_id).delete()
        db.session.commit()
        return render_template("activity_updated.html")
    return "Method Not Allowed", 403

@app.route('/delete_batch/', methods=['POST'])
@is_admin_required
def delete_batch():
    if request.method == 'POST':
        activity_id = session.get('activity_id')
        batch_id = request.form['batch_id']
        Token_batch.query.filter_by(activity_id=activity_id,batch_id=batch_id).delete()
        db.session.commit()
        return render_template("activity_updated.html")
    return "Method Not Allowed", 403

@app.route('/uploads/<filename>', methods=['GET', 'POST'])
@is_admin_required
def download(filename):

    uploads = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_from_directory(uploads, filename,as_attachment=True)


@app.route('/load_token/', methods = ['POST', 'GET'])
def load_token():
    if request.method == 'GET':
        token = request.args.get('token')
        token_id = request.args.get('token_id')
        token_batch_id = request.args.get('batch_id')

        redirect_url = request.args.get('redirect_url')
        if redirect_url:
            response = make_response(redirect(redirect_url))
            session['token'] = token
            session['token_id'] = token_id
            session['token_batch_id'] = token_batch_id
            return response
    return('Something went wrong!')




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001)
