from flask import (
    Blueprint, render_template, redirect,
    url_for, flash, request, session, send_file,
)
from flask_login import login_user, logout_user, login_required, current_user
from app import db
import pyotp
import qrcode
import io
import secrets
from app.models import User, DeviceFingerprint, DeviceApprovalRequest
from datetime import datetime


import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import json
import base64
from app.models import User, DeviceFingerprint, DeviceApprovalRequest, WebAuthnCredential

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
main_bp = Blueprint("main", __name__)


@auth_bp.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ── Session token helpers ─────────────────────────────
def create_session_token(user):
    """Generate a new session token, store it in DB and session."""
    token = secrets.token_hex(32)
    user.session_token = token
    db.session.commit()
    session["session_token"] = token


@auth_bp.before_request
def validate_session_token():
    """Kick out any user whose session token no longer matches the DB."""
    if current_user.is_authenticated:
        stored = session.get("session_token")
        if stored != current_user.session_token:
            logout_user()
            session.clear()
            flash("Your session was terminated.", "warning")
            return redirect(url_for("auth.login"))


@main_bp.route("/")
def home():
    return render_template("home.html")


# ── Register ──────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not all([username, email, password]):
            flash("All fields are required.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif len(password) < 12:
            flash("Password must be at least 12 characters.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("register.html")


# ── Login ─────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

    if session.get("pre_2fa_user_id"):
        user = User.query.get(session["pre_2fa_user_id"])
        if user:
            target = "auth.totp_setup" if not user.totp_enabled else "auth.totp_verify"
            return redirect(url_for(target))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            session["pre_2fa_user_id"] = user.id
            session["remember_me"] = remember
            if user.totp_enabled:
                return redirect(url_for("auth.totp_verify"))
            else:
                return redirect(url_for("auth.totp_setup"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


# ── Logout ────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    # Invalidate session token in DB so all other sessions are killed too
    current_user.session_token = None
    db.session.commit()
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ── TOTP setup ────────────────────────────────────────
@auth_bp.route("/totp/setup")
def totp_setup():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))

    if user.totp_enabled:
        return redirect(url_for("auth.dashboard"))

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    return render_template("totp_setup.html", user=user)


@auth_bp.route("/totp/qr")
def totp_qr():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return "", 404

    user = User.query.get(user_id)
    if not user or not user.totp_secret:
        return "", 404

    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name="ZeroTrustAuth",
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


# ── TOTP confirm (first-time setup) ───────────────────
@auth_bp.route("/totp/confirm", methods=["POST"])
def totp_confirm():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))

    code        = request.form.get("code", "").strip()
    fingerprint = request.form.get("fingerprint", "").strip()
    totp        = pyotp.TOTP(user.totp_secret)

    if totp.verify(code, valid_window=1):
        user.totp_enabled = True
        db.session.commit()

        device, _ = get_or_create_device(user, fingerprint)
        if device:
            session["current_device_id"] = device.id

        flash("TOTP enabled! Now set up Windows Hello.", "success")
        return redirect(url_for("auth.webauthn_register_page"))

    flash("Invalid code. Try again.", "danger")
    return redirect(url_for("auth.totp_setup"))


# -- caluclate risks
def calculate_risk_score(user, device, is_new_device):
    score = 0
    reasons = []

    if is_new_device:
        score += 40
        reasons.append("New device detected")

    elif device and device.is_flagged and not device.is_trusted:
        score += 30
        reasons.append("Device not yet trusted")

    if user.failed_totp_attempts >= 3:
        score += 20 * user.failed_totp_attempts
        reasons.append(f"{user.failed_totp_attempts} failed TOTP attempts")

    current_hour = datetime.utcnow().hour
    if 0 <= current_hour < 5:
        score += 15
        reasons.append("Login during unusual hours (midnight–5 am UTC)")

    print(f"DEBUG risk_score={score} attempts={user.failed_totp_attempts} reasons={reasons}")
    return score, reasons

# ── TOTP verify (every login) ─────────────────────────
@auth_bp.route('/totp/verify', methods=['GET', 'POST'])
def totp_verify():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code        = request.form.get('code', '').strip()
        fingerprint = request.form.get('fingerprint', '').strip()
        print(f"FINGERPRINT: '{fingerprint[:20] if fingerprint else 'EMPTY'}'")

        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code, valid_window=1):
            device, is_new = get_or_create_device(user, fingerprint)

            score, reasons = calculate_risk_score(user, device, is_new)

            user.failed_totp_attempts = 0
            db.session.commit()

            if score >= 70:
                session['risk_score']   = score
                session['risk_reasons'] = reasons
                session.pop('pre_2fa_user_id', None)
                session.pop('remember_me', None)
                return redirect(url_for('auth.risk_blocked'))

            if score >= 40:
                # Store everything needed for step-up
                session['stepup_user_id']      = user.id
                session['stepup_remember']     = session.pop('remember_me', False)
                session['stepup_risk_score']   = score
                session['stepup_risk_reasons'] = reasons
                if device:
                    session['stepup_device_id'] = device.id
                session.pop('pre_2fa_user_id', None)
                return redirect(url_for('auth.webauthn_stepup_page'))

            if device and not device.is_trusted:
                session['pending_device_id'] = device.id
                flash('This device is pending approval.', 'warning')
                return redirect(url_for('auth.device_pending'))

            remember = session.pop('remember_me', False)
            session.pop('pre_2fa_user_id', None)
            if device:
                session['current_device_id'] = device.id
            login_user(user, remember=remember)
            create_session_token(user)
            return redirect(url_for('auth.dashboard'))

        else:
            user.failed_totp_attempts = (user.failed_totp_attempts or 0) + 1
            db.session.commit()
            flash('Invalid 2FA code.', 'danger')

    # ← this line must be at THIS indentation level — outside the if POST block
    return render_template('totp_verify.html')

# -- blocked 
@auth_bp.route('/risk/blocked')
def risk_blocked():
    score   = session.pop('risk_score',   None)
    reasons = session.pop('risk_reasons', [])
    if not score:
        return redirect(url_for('auth.login'))
    return render_template('risk_blocked.html',
                           score=score, reasons=reasons)


RP_ID   = 'localhost'
RP_NAME = 'ZeroTrustAuth'
ORIGIN  = 'http://localhost:5000'


# ── WebAuthn registration options ─────────────────────
@auth_bp.route('/webauthn/register/options', methods=['POST'])
def webauthn_register_options():
    user_id = session.get('pre_2fa_user_id') or (
        current_user.id if current_user.is_authenticated else None
    )
    if not user_id:
        return {'error': 'Not authenticated'}, 401

    user = User.query.get(user_id)
    if not user:
        return {'error': 'User not found'}, 404

    # Exclude already registered credentials
    existing = WebAuthnCredential.query.filter_by(user_id=user.id).all()
    exclude_credentials = [
        webauthn.helpers.structs.PublicKeyCredentialDescriptor(
            id=base64.urlsafe_b64decode(c.credential_id + '==')
        )
        for c in existing
    ]

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
        ),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
        exclude_credentials=exclude_credentials,
    )

    session['webauthn_reg_challenge'] = base64.urlsafe_b64encode(
        options.challenge
    ).rstrip(b'=').decode()

    return json.loads(webauthn.options_to_json(options))


# ── WebAuthn registration verify ──────────────────────
@auth_bp.route('/webauthn/register/verify', methods=['POST'])
def webauthn_register_verify():
    user_id = session.get('pre_2fa_user_id') or (
        current_user.id if current_user.is_authenticated else None
    )
    if not user_id:
        return {'error': 'Not authenticated'}, 401

    user = User.query.get(user_id)
    if not user:
        return {'error': 'User not found'}, 404

    challenge_b64 = session.get('webauthn_reg_challenge')
    if not challenge_b64:
        return {'error': 'No challenge found'}, 400

    challenge = base64.urlsafe_b64decode(challenge_b64 + '==')

    try:
        data = request.get_json()

        reg_cred = webauthn.helpers.structs.RegistrationCredential(
            id=data['id'],
            raw_id=base64.urlsafe_b64decode(data['rawId'] + '=='),
            response=webauthn.helpers.structs.AuthenticatorAttestationResponse(
                client_data_json=base64.urlsafe_b64decode(
                    data['response']['clientDataJSON'] + '=='
                ),
                attestation_object=base64.urlsafe_b64decode(
                    data['response']['attestationObject'] + '=='
                ),
            ),
            type=data.get('type', 'public-key'),
        )

        verification = webauthn.verify_registration_response(
            credential=reg_cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:
        return {'error': str(e)}, 400

    cred = WebAuthnCredential(
        user_id=user.id,
        credential_id=base64.urlsafe_b64encode(
            verification.credential_id
        ).rstrip(b'=').decode(),
        public_key=base64.urlsafe_b64encode(
            verification.credential_public_key
        ).rstrip(b'=').decode(),
        sign_count=verification.sign_count,
    )
    db.session.add(cred)
    db.session.commit()
    session.pop('webauthn_reg_challenge', None)

    if session.get('pre_2fa_user_id'):
        remember = session.pop('remember_me', False)
        session.pop('pre_2fa_user_id', None)
        login_user(user, remember=remember)
        create_session_token(user)

    return {'success': True, 'redirect': url_for('auth.dashboard')}
# ── WebAuthn step-up options ───────────────────────────
@auth_bp.route('/webauthn/stepup/options', methods=['POST'])
def webauthn_stepup_options():
    user_id = session.get('stepup_user_id')
    if not user_id:
        return {'error': 'No step-up session'}, 401

    user = User.query.get(user_id)
    if not user:
        return {'error': 'User not found'}, 404

    credentials = WebAuthnCredential.query.filter_by(user_id=user.id).all()
    if not credentials:
        return {'error': 'No credentials registered'}, 400

    allow_credentials = [
        webauthn.helpers.structs.PublicKeyCredentialDescriptor(
            id=base64.urlsafe_b64decode(c.credential_id + '==')
        )
        for c in credentials
    ]

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session['webauthn_auth_challenge'] = base64.urlsafe_b64encode(
        options.challenge
    ).rstrip(b'=').decode()

    return json.loads(webauthn.options_to_json(options))


# ── WebAuthn step-up verify ────────────────────────────
@auth_bp.route('/webauthn/stepup/verify', methods=['POST'])
def webauthn_stepup_verify():
    user_id = session.get('stepup_user_id')
    if not user_id:
        return {'error': 'No step-up session'}, 401

    challenge_b64 = session.get('webauthn_auth_challenge')
    if not challenge_b64:
        return {'error': 'No challenge'}, 400

    challenge = base64.urlsafe_b64decode(challenge_b64 + '==')
    data       = request.get_json()

    cred_id_b64 = data.get('id', '')
    cred = WebAuthnCredential.query.filter_by(
        credential_id=cred_id_b64
    ).first()
    if not cred:
        return {'error': 'Credential not found'}, 404

    try:
        auth_cred = webauthn.helpers.structs.AuthenticationCredential(
            id=data['id'],
            raw_id=base64.urlsafe_b64decode(data['rawId'] + '=='),
            response=webauthn.helpers.structs.AuthenticatorAssertionResponse(
                client_data_json=base64.urlsafe_b64decode(
                    data['response']['clientDataJSON'] + '=='
                ),
                authenticator_data=base64.urlsafe_b64decode(
                    data['response']['authenticatorData'] + '=='
                ),
                signature=base64.urlsafe_b64decode(
                    data['response']['signature'] + '=='
                ),
                user_handle=base64.urlsafe_b64decode(
                    data['response']['userHandle'] + '=='
                ) if data['response'].get('userHandle') else None,
            ),
            type=data.get('type', 'public-key'),
        )

        verification = webauthn.verify_authentication_response(
            credential=auth_cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64.urlsafe_b64decode(
                cred.public_key + '=='
            ),
            credential_current_sign_count=cred.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        return {'error': str(e)}, 400

    cred.sign_count = verification.new_sign_count
    db.session.commit()

    if session.get('stepup_device_id'):
        device = DeviceFingerprint.query.get(session['stepup_device_id'])
        if device:
            device.is_trusted = True
            device.is_flagged = False
            # Resolve any pending approval request
            approval = DeviceApprovalRequest.query.filter_by(
                device_id=device.id, status='pending'
            ).first()
            if approval:
                approval.status = 'approved'
                approval.resolved_at = datetime.utcnow()
            db.session.commit()

    user = User.query.get(user_id)
    remember = session.pop('stepup_remember', False)
    session.pop('stepup_user_id', None)
    session.pop('webauthn_auth_challenge', None)
    if session.get('stepup_device_id'):
        session['current_device_id'] = session.pop('stepup_device_id')
    login_user(user, remember=remember)
    create_session_token(user)

    return {'success': True, 'redirect': url_for('auth.dashboard')}
    user_id = session.get('stepup_user_id')
    if not user_id:
        return {'error': 'No step-up session'}, 401

    challenge_b64 = session.get('webauthn_auth_challenge')
    if not challenge_b64:
        return {'error': 'No challenge'}, 400

    challenge = base64.urlsafe_b64decode(challenge_b64 + '==')
    data       = request.get_json()

    cred_id_b64 = data.get('id', '')
    cred = WebAuthnCredential.query.filter_by(
        credential_id=cred_id_b64
    ).first()
    if not cred:
        return {'error': 'Credential not found'}, 404

    try:
        auth_cred = webauthn.helpers.structs.AuthenticationCredential.model_validate(data)
        verification = webauthn.verify_authentication_response(
            credential=auth_cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64.urlsafe_b64decode(
                cred.public_key + '=='
            ),
            credential_current_sign_count=cred.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        return {'error': str(e)}, 400

    cred.sign_count = verification.new_sign_count
    db.session.commit()

    user = User.query.get(user_id)
    remember = session.pop('stepup_remember', False)
    session.pop('stepup_user_id', None)
    session.pop('webauthn_auth_challenge', None)
    if session.get('stepup_device_id'):
        session['current_device_id'] = session.pop('stepup_device_id')
    login_user(user, remember=remember)
    create_session_token(user)

    return {'success': True, 'redirect': url_for('auth.dashboard')}


@auth_bp.route('/webauthn/stepup/fallback')
def webauthn_stepup_fallback():
    user_id   = session.get('stepup_user_id')
    device_id = session.get('stepup_device_id')

    if not user_id or not device_id:
        return redirect(url_for('auth.login'))

    # Move session state back to pre_2fa format for device_pending
    session['pre_2fa_user_id']  = user_id
    session['pending_device_id'] = device_id
    session['remember_me']       = session.get('stepup_remember', False)

    # Clean up stepup session keys
    session.pop('stepup_user_id', None)
    session.pop('stepup_remember', None)
    session.pop('stepup_risk_score', None)
    session.pop('stepup_risk_reasons', None)

    flash('Windows Hello unavailable. Waiting for manual approval.', 'warning')
    return redirect(url_for('auth.device_pending'))

@auth_bp.route('/webauthn/stepup')
def webauthn_stepup_page():
    user_id = session.get('stepup_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    risk_score   = session.get('stepup_risk_score', 0)
    risk_reasons = session.get('stepup_risk_reasons', [])
    return render_template('webauthn_stepup.html',
                           risk_score=risk_score,
                           risk_reasons=risk_reasons)


@auth_bp.route('/webauthn/register')
def webauthn_register_page():
    user_id = session.get('pre_2fa_user_id') or (
        current_user.id if current_user.is_authenticated else None
    )
    if not user_id:
        return redirect(url_for('auth.login'))
    return render_template('webauthn_register.html')


# ── Device pending ────────────────────────────────────
@auth_bp.route("/device/pending")
def device_pending():
    device_id    = session.get("pending_device_id")
    user_id      = session.get("pre_2fa_user_id")
    risk_warning = session.get("risk_warning")  # get not pop — keep it for dashboard

    if not device_id or not user_id:
        return redirect(url_for("auth.login"))

    device = DeviceFingerprint.query.filter_by(
        id=device_id,
        user_id=user_id
    ).first()

    if not device:
        return redirect(url_for("auth.login"))

    if device.is_trusted:
        user = User.query.get(user_id)
        remember = session.pop("remember_me", False)
        session.pop("pre_2fa_user_id", None)
        session.pop("pending_device_id", None)
        session["current_device_id"] = device.id
        login_user(user, remember=remember)
        create_session_token(user)
        flash("Device approved. Welcome!", "success")
        return redirect(url_for("auth.dashboard"))

    return render_template("device_pending.html",
                           device=device,
                           risk_warning=risk_warning)


# ── Device helpers ────────────────────────────────────
def get_or_create_device(user, fingerprint_hash):
    if not fingerprint_hash:
        return None, False

    device = DeviceFingerprint.query.filter_by(
        user_id=user.id,
        fingerprint_hash=fingerprint_hash
    ).first()

    if device:
        device.last_seen = datetime.utcnow()
        db.session.commit()
        return device, False

    existing_count = DeviceFingerprint.query.filter_by(
        user_id=user.id
    ).count()
    is_first_device = existing_count == 0

    device = DeviceFingerprint(
        user_id=user.id,
        fingerprint_hash=fingerprint_hash,
        label=fingerprint_hash[:8],
        is_trusted=is_first_device,
        is_flagged=not is_first_device
    )
    db.session.add(device)
    db.session.flush()

    if not is_first_device:
        approval = DeviceApprovalRequest(
            user_id=user.id,
            device_id=device.id,
            status="pending"
        )
        db.session.add(approval)

    db.session.commit()
    return device, not is_first_device


@auth_bp.route("/devices/trust/<int:device_id>", methods=["POST"])
@login_required
def trust_device(device_id):
    device = DeviceFingerprint.query.filter_by(
        id=device_id, user_id=current_user.id
    ).first_or_404()

    device.is_trusted = True
    device.is_flagged = False

    approval = DeviceApprovalRequest.query.filter_by(
        device_id=device_id, status="pending"
    ).first()
    if approval:
        approval.status = "approved"
        approval.resolved_at = datetime.utcnow()

    db.session.commit()
    flash("Device marked as trusted.", "success")
    return redirect(url_for("auth.dashboard"))


@auth_bp.route("/devices/remove/<int:device_id>", methods=["POST"])
@login_required
def remove_device(device_id):
    device = DeviceFingerprint.query.filter_by(
        id=device_id, user_id=current_user.id
    ).first_or_404()

    is_current_device = session.get("current_device_id") == device_id

    # Invalidate the device owner's session token —
    # forces them out on their next request even if currently logged in
    owner = User.query.get(device.user_id)
    if owner and owner.id != current_user.id:
        owner.session_token = None
        db.session.commit()

    DeviceApprovalRequest.query.filter_by(device_id=device_id).delete()
    db.session.delete(device)
    db.session.commit()

    if is_current_device:
        logout_user()
        session.clear()
        flash("Your current device was removed. You have been logged out.", "warning")
        return redirect(url_for("auth.login"))

    flash("Device removed.", "info")
    return redirect(url_for("auth.dashboard"))




# ── Cancel auth ───────────────────────────────────────
@auth_bp.route("/cancel", methods=["GET", "POST"])
def cancel_auth():
    session.pop("pre_2fa_user_id", None)
    session.pop("remember_me", None)
    flash("Authentication canceled.", "info")
    return redirect(url_for("main.home"))


# ── Dashboard ─────────────────────────────────────────
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    new_device   = session.pop('new_device_warning', False)
    risk_warning = session.pop('risk_warning', None)

    devices = DeviceFingerprint.query.filter_by(
        user_id=current_user.id
    ).order_by(DeviceFingerprint.last_seen.desc()).all()

    pending_requests = DeviceApprovalRequest.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).all()

    return render_template('dashboard.html',
                           user=current_user,
                           devices=devices,
                           new_device=new_device,
                           pending_requests=pending_requests,
                           risk_warning=risk_warning)