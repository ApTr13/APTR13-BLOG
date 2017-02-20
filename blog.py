import os
import re
from string import letters
import random
import hashlib
import hmac

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(
    template_dir), autoescape=True)

SECRET = "thisistopsecretstuff"


# Creating Jinja Environment and secure connection using SECRET
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Primary Handler that helps in rendering pages,
# set cookies, login and logout.
class HandlerFunction(webapp2.RequestHandler):
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s = %s; Path = /' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id = ; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Functions to create and check hashed passwords
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return "%s,%s" % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# Database Model for all Users that Signup
class User (db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# Functions to validate User Signup 
def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+.[\S]+$')
    return not email or EMAIL_RE.match(email)


# Handler for Proper signup
class SignupHandler(HandlerFunction):
    def get(self):
        if not self.user:
            self.render('signup.html', currentuser="")
        else:
            msg = "You are already logged in, %s" % self.user.name
            self.render('signup.html', msg=msg, currentuser=self.user.name)

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = {}
        params['email'] = self.email
        params['username'] = self.username
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', currentuser="", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise notImplementedError


# Register Handler that checks if user prexists or not
class RegisterHandler(SignupHandler):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render('signup.html', error_username=msg, currentuser="")
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            user = self.username
            self.redirect('/blog')


# Login Handler that verifies User who tries to login
class Login(HandlerFunction):
    def get(self):
        if not self.user:
            self.render('login.html', currentuser="")
        else:
            msg = "You are already logged in, %s" % self.user.name
            self.render('login.html', msg=msg)

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        params = {}
        params['password'] = self.password
        params['username'] = self.username
        u = User.by_name(self.username)
        if u and valid_pw(self.username, self.password, u.pw_hash):
            self.login(u)
            user = self.username
            self.redirect('/blog')
        elif params['username']:
            params['error_login'] = "Please Enter a Valid Password to login."
            params['currentuser'] = ""
            self.render('login.html', **params)
        elif params['password']:
            params['error_login'] = "You cannot login without a username."
            params['currentuser'] = ""
            self.render('login.html', **params)

# Clear all cookies after Logout
class Logout(HandlerFunction):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Post model for handling all Post's info in database
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)

    def render(self):
        self.update_post()
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("permalink.html", post=self)


# Function for rendering the home page, showing all blogs
class BlogFront(HandlerFunction):
    def get(self):
        posts = db.GqlQuery(
            "SELECT * FROM Post "+"ORDER BY last_modified DESC")
        if self.user:
            self.render('front.html', posts=posts, currentuser=self.user.name)
        else:
            self.render('front.html', posts=posts, currentuser="")


# Function for rendering a particular Post and its comments
class PostPage(HandlerFunction):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery(
            "SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", post_id)

        if not post:
            self.error(404)
            return
        if self.user:
            self.render(
                "permalink.html", post=post, currentuser=self.user.name, comments=comments)
        else:
            self.render(
                "permalink.html", post=post, currentuser="", comments=comments)


# Function for publishing new post by a logged in user
class NewPost(HandlerFunction):
    def get(self):
        uid = self.read_secure_cookie('user_id')
        if self.user:
            if User.by_id(int(uid)).name == self.user.name:
                self.render('newpost.html', currentuser=self.user.name)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')

    def post(self):
        uid = self.read_secure_cookie('user_id')
        if self.user:
            if User.by_id(int(uid)).name == self.user.name:
                subject = self.request.get('subject')
                content = self.request.get('content')
                uid = self.read_secure_cookie('user_id')
                author = User.by_id(int(uid)).name

                if subject and content and author:
                    p = Post(parent=blog_key(), subject=subject, content=content, author=author)
                    p.put()
                    self.redirect('/blog/%s' % str(p.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render(
                        'newpost.html', subject=subject, content=content, error=error, currentuser=self.user.name)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')


# Function to Edit a given post by the author himself 
class EditPost(HandlerFunction):
    def get(self):
        postid = self.request.get("postid")
        comments = db.GqlQuery(
            "SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", postid)
        if postid:
            postid = int(postid)
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(key)
        u = User.by_name(self.user.name)

        if p:
            error = ""
        if u.name != p.author:
            msg = "Hey!!! You can only edit your own posts!"
            self.render('permalink.html', post=p, msg=msg, comments=comments,
                        currentuser=self.user.name)
        else:
            self.render(
                'editpost.html', p=p, error=error, postid=postid, u=u, currentuser=self.user.name)

    def post(self, button=None):
        postid = self.request.get("postid")
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(key)
        if key and p.author == self.user.name:
            p = db.get(key)
            if self.request.get('button') == 'Edit':
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    p.subject = subject
                    p.content = content
                    p.put()
                else:
                    self.write('none')
                self.redirect('/blog')
            elif self.request.get('button') == "Cancel":
                self.redirect('/blog')
        else:
            self.redirect('/blog/delete/%s' % postid)


# Deleting a post by it's author himself
class DeletePost(HandlerFunction):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        comments = db.GqlQuery("SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", post_id)
        if key:
            p = db.get(key)
            u = self.user
            if u.name != p.author:
                msg = "Hey!!! You can only delete your own posts!"
                self.render('permalink.html', post=p, comments=comments, msg=msg,
                            currentuser=self.user.name)
            else:
                self.render('deletepost.html', p=p, post_id=post_id,
                            currentuser=self.user.name)
        else:
            msg = ""
            self.render('permalink.html', post=p, comments=comments, msg=msg,
                        currentuser=self.user.name)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        if key:
            p = db.get(key)
            if self.user.name == p.author:
                if self.request.get('button') == 'Delete':
                    p.delete()
                    self.redirect('/blog')
                elif self.request.get('button') == 'Cancel':
                    self.redirect('/blog')
            else:
                self.redirect('/blog')
        else:
            self.redirect('/blog')

# Comment model that stores data of comments with each post
class Comment(db.Model):
    post = db.ReferenceProperty(Post, collection_name="comments")
    post_id = db.StringProperty(required=True)
    commentor = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    comment = db.TextProperty(required=True)
    like = db.BooleanProperty()

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')


# Function that renders page for writing comments on other's posts
class CommentPost(HandlerFunction):
    def get(self):
        postid = self.request.get("postid")
        comments = db.GqlQuery("SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", postid)
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(key)
        u = self.user
        if p:
            error = ""
        commentid = self.request.get("commentid")
        if commentid:
            key_c = db.Key.from_path('Comment', int(commentid),
                                     parent=blog_key())
            c = db.get(key_c)
            comment = c.comment
        else:
            comment = ""
        if u.name != p.author:
            self.render('newcomment.html', comments=comments, post=p,
                        comment=comment, currentuser=self.user.name)
        else:
            msg = "Hey!!! You cannot comment on your own posts!"
            self.render('permalink.html', post=p, msg=msg, comments=comments,
                        currentuser=self.user.name)

    def post(self):
        postid = self.request.get("postid")
        commentid = self.request.get("commentid")
        checkbox = self.request.get('like')
        if checkbox == "checked":
            like = True
        else:
            like = False

        if self.request.get('button') == "Add Comment":
            if commentid:
                key_c = db.Key.from_path('Comment', int(commentid),
                                         parent=blog_key())
                c = db.get(key_c)
                c.comment = self.request.get('comment')
                c.like = like
                c.put()
                key = db.Key.from_path('Post', int(postid), parent=blog_key())
                p = db.get(key)
                msg = "Your changes were saved!"
                like = checkbox
                self.render('newcomment.html', post=p, like=like, comment=c.comment,
                            msg=msg)
            else:
                commentor = self.user.name
                comment = self.request.get('comment')
                if comment or like:
                    c = Comment(parent=blog_key(), post_id=postid,
                                commentor=commentor,
                                comment=comment, like=like)
                    c.put()
                    key = db.Key.from_path('Post', int(postid),
                                           parent=blog_key())
                    p = db.get(key)
                    msg = "Your changes were saved!"
                    like = checkbox
                    self.render('newcomment.html', post=p, like=like,
                                comment=comment, msg=msg)
        elif self.request.get('button') == "Cancel":
            self.redirect('/blog')


# Function to delete any comment by the commentor himself
class DeleteComment(HandlerFunction):
    def get(self):
        postid = self.request.get("postid")
        commentid = self.request.get("commentid")
        comments = db.GqlQuery("SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", postid)
        keyp = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(keyp)
        key = db.Key.from_path('Comment', int(commentid), parent=blog_key())
        if key:
            c = db.get(key)
            if c.commentor != self.user.name:
                msg = "Sorry, you can only delete your own comments!"
                self.render(
                    'permalink.html', post=p, msg=msg, comments=comments, currentuser=self.user.name)
            else:
                self.render('deletecomment.html', c=c, commentid=commentid,
                            currentuser=self.user.name)
        else:
            self.render('permalink.html', post=p, msg=msg, comments=comments,
                        currentuser=self.user.name)

    def post(self):
        postid = self.request.get("postid")
        commentid = self.request.get("commentid")
        comments = db.GqlQuery("SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", postid)
        keyp = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(keyp)
        key = db.Key.from_path('Comment', int(commentid), parent=blog_key())
        if key:
            c = db.get(key)
            if c.commentor != self.user.name:
                msg = "You can only delete your comments!"
                self.render('permalink.html', post=p, msg=msg, comments=comments, currentuser=self.user.name)
            else:
                if self.request.get('button') == 'Delete':
                    c.delete()
                    self.redirect('/blog')
                elif self.request.get('button') == 'Cancel':
                    self.redirect('/blog/comment/?postid=%s' % (postid))
        else:
            self.render('permalink.html', post=p, msg=msg, comments=comments,
                        currentuser=self.user.name)


# Edit a comment, done by the commentor himself
class EditComment(HandlerFunction):
    def get(self):
        postid = self.request.get("postid")
        comments = db.GqlQuery("SELECT * FROM Comment "+"WHERE post_id= :1 "+"ORDER BY last_modified DESC", postid)
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        valid_P_ID = False
        valid_C_ID = False
        if key:
            p = db.get(key)
            u = User.by_name(self.user.name)
            valid_P_ID = True
        commentid = self.request.get("commentid")
        if commentid:
            key_c = db.Key.from_path('Comment', int(commentid),
                                     parent=blog_key())
            c = db.get(key_c)
            if c.commentor == self.user.name:
                comment = c.comment
                valid_C_ID = True
        else:
            comment = ""

        print valid_C_ID
        print valid_P_ID
        if self.user.name == c.commentor and valid_C_ID and valid_P_ID:
            self.render('editcomment.html', c=c, post=p, comment=comment,
                        currentuser=self.user.name)
        elif self.user.name != c.commentor:
            msg = "Sorry, You cannot edit other users' comments!"
            self.render('permalink.html', post=p, msg=msg, comments=comments,
                        currentuser=self.user.name)
        else:
            msg = ""
            self.render('permalink.html', post=p, msg=msg, comments=comments,
                        currentuser=self.user.name)

    def post(self):
        postid = self.request.get("postid")
        commentid = self.request.get("commentid")
        checkbox = self.request.get('like')
        valid_C_ID = False
        valid_P_ID = False
        if checkbox == "checked":
            like = True
        else:
            like = False
        if self.request.get('button') == "Edit Comment":
            if commentid and postid:
                key_c = db.Key.from_path('Comment', int(commentid),
                                         parent=blog_key())
                if key_c:
                    c = db.get(key_c)
                    c.comment = self.request.get('comment')
                    c.like = like
                    c.put()
                    key = db.Key.from_path(
                        'Post', int(postid), parent=blog_key())
                if key:
                    p = db.get(key)
                    msg = "Your changes were saved!"
                    like = checkbox
                    self.render('newcomment.html', post=p, like=like, comment=c.comment,
                                msg=msg, currentuser=self.user.name)
                else:
                    self.redirect('/blog')
            else:
                commentor = self.user.name
                comment = self.request.get('comment')
                if comment or like:
                    c = Comment(parent=blog_key(), post_id=postid,
                                commentor=commentor,
                                comment=comment, like=like)
                    c.put()
                    key = db.Key.from_path('Post', int(postid),
                                           parent=blog_key())
                    p = db.get(key)
                    msg = "Your changes were saved!"
                    like = checkbox
                    self.render('newcomment.html', post=p, like=like,
                                comment=comment, msg=msg)
        elif self.request.get('button') == "Cancel":
            self.redirect('/blog')

# Routing links of the application with their respective classes
app = webapp2.WSGIApplication([('/signup', RegisterHandler),
                               ('/', BlogFront),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/?', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/comment/?', CommentPost),
                               ('/blog/comment/edit/?', EditComment),
                               ('/blog/comment/delete/?', DeleteComment)
                               ],
                              debug=True)
