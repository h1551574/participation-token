import functools
from flask import request, session

# Wrapper that checks if the user has admin rights
# Admin rights are assigned in session during lti launch
# based on the users role provided by the platform.
def is_admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if session.get('is_admin') is None:
            print("No Admin Cookie!")
            return 'Unable to ckeck permissions! (Try to disable private mode)',403

        if not session['is_admin']:
            return 'You are not authorized to view this page!',403
        return view(**kwargs)
    return wrapped_view
