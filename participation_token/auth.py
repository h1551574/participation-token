import functools
from flask import request, session

# Wrapper that checks if the user has admin rights
# Admin rights are assigned in session during lti launch
# based on the users role provided by the platform.
def is_admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if session.get('is_admin') is None:
            return 'Unable to ckeck permissions! (Try to disable private mode)',403

        if not session['is_admin']:
            return 'You are not authorized to view this page!',403
        return view(**kwargs)
    return wrapped_view

# Wrapper that checks if the an admin user is not accessing content which is not related to his activity
def is_activity_id_matching(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if session.get('activity_id') is None:
            return 'Unable to ckeck permissions! (Try to disable private mode)',403
        requested_activity = request.form['activity_id']

        if requested_activity != session['activity_id']:
            return 'You are not authorized to view this page!',403
        return view(**kwargs)
    return wrapped_view
