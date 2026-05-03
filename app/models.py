from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    failed_totp_attempts = db.Column(db.Integer, default=0)

    session_token = db.Column(db.String(64), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class DeviceFingerprint(db.Model):
    __tablename__ = "device_fingerprints"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    fingerprint_hash = db.Column(db.String(64), nullable=False)
    label = db.Column(db.String(120), nullable=True)
    is_trusted = db.Column(db.Boolean, default=False)
    is_flagged = db.Column(db.Boolean, default=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("devices", lazy=True))

    def __repr__(self):
        return f"<Device {self.fingerprint_hash[:8]} user={self.user_id}>"


class WebAuthnCredential(db.Model):
    tablename = 'webauthn_credentials'

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    credential_id     = db.Column(db.Text, unique=True, nullable=False)
    public_key        = db.Column(db.Text, nullable=False)
    sign_count        = db.Column(db.Integer, default=0)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('webauthn_credentials', lazy=True))


class DeviceApprovalRequest(db.Model):
    __tablename__ = "device_approval_requests"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey("device_fingerprints.id"), nullable=False)

    status = db.Column(db.String(20), default="pending")  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref=db.backref("approval_requests", lazy=True))
    device = db.relationship("DeviceFingerprint", backref=db.backref("approval_requests", lazy=True))

    def __repr__(self):
        return f"<DeviceApprovalRequest device={self.device_id} status={self.status}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))