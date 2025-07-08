from flask import Flask, Response, request, render_template, redirect, url_for, send_file, send_from_directory, flash, abort, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from datetime import datetime, timezone
from pytz import timezone, utc
from functools import wraps
from sqlalchemy import MetaData, text
from enum import Enum
from urllib.parse import unquote

import smtplib
import csv 
import zipfile
import os
import io
import subprocess
import requests

if os.getenv("RENDER") != "true":
    from dotenv import load_dotenv
    load_dotenv()


# --- CONFIG ---

EMAIL = os.getenv("EMAIL", "false").lower() == "true"
LOCAL_TEST = os.getenv("LOCAL_TEST", "false").lower() == "true"
MAX_EMAILS = int(os.getenv("MAX_EMAILS"))
WAITING_TEST = os.getenv("WAITING_TEST", "false").lower() == "true"
CAPTCHA = os.getenv("CAPTCHA", "false").lower() == "true"

PARIS_TZ = timezone("Europe/Paris")

TOKEN_TIME = 60 * 60 * 24  # valable un jour
WAITING_TIME = 60 * 5 if WAITING_TEST else 60 * 60 * 24 # seconds
SHORT_WAITING_TIME = 60 * 60 * 24 if WAITING_TEST else 60 * 60

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")  
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")  
CRON_SECRET = os.getenv("CRON_SECRET")

EQUIPE = os.getenv("EQUIPE")

app = Flask(__name__)
app.config['SERVER_NAME'] = 'localhost:5000' if LOCAL_TEST else os.getenv('SERVER_NAME')
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///event.db' if LOCAL_TEST else os.getenv('DATABASE_URL')
if not LOCAL_TEST:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "connect_args": {
            "sslmode": "require"
        }
    }
app.config['SECURITY_TOKEN_MAX_AGE'] = TOKEN_TIME
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv("RECAPTCHA_SECRET_KEY")
app.config['RECAPTCHA_SITE_KEY'] = os.getenv("RECAPTCHA_SITE_KEY")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

db = SQLAlchemy(app) if LOCAL_TEST else SQLAlchemy(app, metadata=MetaData(schema="public"))
token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    # storage_uri="redis://localhost:6379"
)

# --- MODELES ---

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    date = db.Column(db.Date, nullable=False)
    active = db.Column(db.Boolean, default=False)
    
class Utilisateur(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    prenom = db.Column(db.String(100), nullable=True)
    nom = db.Column(db.String(100), nullable=True)
    paid = db.Column(db.Boolean, default=False)
    creation_date = db.Column(db.DateTime, default=lambda:datetime.now(PARIS_TZ))

    table_args__ = (
        db.UniqueConstraint('email', 'event_id', name='uq_email_event'),
    )

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)
    inscription_date = db.Column(db.DateTime, default=lambda:datetime.now(PARIS_TZ))
    
class Attente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)
    contacted = db.Column(db.Boolean, default=False)
    inscription_date = db.Column(db.DateTime, default=lambda:datetime.now(PARIS_TZ))
    
class NotificationStatus(Enum):
    PENDING = "pending"
    RESPONDED = "responded"
    EXPIRED = "expired"
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)    
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(PARIS_TZ))
    expires_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default=NotificationStatus.PENDING.value, nullable=False)
    processed_at = db.Column(db.DateTime, nullable=True)
    
class PlacesLiberees(db.Model):
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), primary_key=True)
    compteur = db.Column(db.Integer, default=0)
    
class CompteurEmails(db.Model):
    date = db.Column(db.Date, primary_key=True)
    count = db.Column(db.Integer, default=0)
    
class Emails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(PARIS_TZ))
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    html = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending')
    error_message = db.Column(db.Text, nullable=True)
    
class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(PARIS_TZ))
    endpoint = db.Column(db.String(100))
    ip = db.Column(db.String(45))
    email = db.Column(db.String(120))


# --- OUTILS ---

def send_email(to_email, subject, html_body):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    from_email = os.getenv("GMAIL")
    password = os.getenv("SMTP_PASSWORD")
    
    msg = MIMEText(html_body, 'html')
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    email_log = Emails(
        email=to_email,
        subject=subject,
        html=html_body
    )

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(from_email, password)
            server.send_message(msg)
            
        email_log.status = "sent"
        
    except Exception as e:
        email_log.status = "failed"
        email_log.error_message = str(e)
        
    today = datetime.now(PARIS_TZ).date()
    compteur = CompteurEmails.query.filter_by(date=today).first()

    if not compteur:
        compteur = CompteurEmails(date=today, count=1)
        db.session.add(compteur)
    else:
        compteur.count += 1
    db.session.commit()
    
    # Log de l'e-mail
    db.session.add(email_log)
    db.session.commit()


def waiting_time(event_id):
    event = Event.query.get(event_id)
    if not event:
        return 0

    event_datetime = PARIS_TZ.localize(datetime.combine(event.date, datetime.min.time()))
    now = datetime.now(PARIS_TZ)

    if now <= event_datetime - timedelta(hours=18):
        return WAITING_TIME
    elif now <= event_datetime:
        return SHORT_WAITING_TIME
    else:
        return 0
    

def verify_captcha(token):
    secret = app.config['RECAPTCHA_SECRET_KEY']
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
        'secret': secret,
        'response': token
    })
    return response.json().get('success', False)


def check_auth(username, password):
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def authenticate():
    return Response(
        'Access denied.\n'
        'Please provide a valid password.', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


EXPORT_DIR = "exports"

def export_csv(event_id):
    event = Event.query.filter_by(id=event_id).first()        
    
    if not os.path.exists(EXPORT_DIR):
        os.makedirs(EXPORT_DIR)
    else:
        # Supprime tous les fichiers CSV/ZIP existants
        for file in os.listdir(EXPORT_DIR):
            if file.endswith(".csv") or file.endswith(".zip"):
                os.remove(os.path.join(EXPORT_DIR, file))

    # Date/heure actuelle pour suffix
    now_paris = datetime.now(PARIS_TZ)
    timestamp = now_paris.strftime("%Y-%m-%d_%Hh%M")

    filenames = []

    # Requêtes
    participants = db.session.query(Utilisateur).filter(
        Utilisateur.event_id == event.id,
        Utilisateur.id.in_(
            db.session.query(Participant.utilisateur_id)
        )
    ).all()
    non_payes = [u for u in participants if not u.paid]
    payes_non_participants = db.session.query(Utilisateur).filter(
        Utilisateur.event_id == event.id,
        Utilisateur.paid == True,
        ~Utilisateur.id.in_(
            db.session.query(Participant.utilisateur_id)
        )
    ).all()

    # 1. Participants
    p_file = f"participants_{event.name}_{timestamp}.csv"
    with open(os.path.join(EXPORT_DIR, p_file), "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["Email", "Prénom", "Nom"])
        for u in participants:
            writer.writerow([u.email, u.prenom or "", u.nom or ""])
    filenames.append(p_file)

    # 2. A faire payer
    np_file = f"a_faire_payer_{event.name}_{timestamp}.csv"
    with open(os.path.join(EXPORT_DIR, np_file), "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["Email", "Prénom", "Nom"])
        for u in non_payes:
            writer.writerow([u.email, u.prenom or "", u.nom or ""])
    filenames.append(np_file)

    # 3. A rembourser
    pp_file = f"a_rembourser_{event.name}_{timestamp}.csv"
    with open(os.path.join(EXPORT_DIR, pp_file), "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["Email", "Prénom", "Nom"])
        for u in payes_non_participants:
            writer.writerow([u.email, u.prenom or "", u.nom or ""])
    filenames.append(pp_file)

    # Création du zip
    zip_name = f"export_{event.name}_{timestamp}.zip"
    zip_path = os.path.join(EXPORT_DIR, zip_name)
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for file in filenames:
            zipf.write(os.path.join(EXPORT_DIR, file), arcname=file)

    print(f"Export terminé : {zip_name} généré pour le {event.name} avec {len(filenames)} fichiers.")

    return zip_name  # on retourne le nom du fichier .zip pour usage dans Flask


def get_current_event():
    event_id = session.get('event_id')
    if not event_id:
        return None
    return Event.query.get(event_id)

# --- ROUTES ---

@app.route('/select')
def index():
    events = Event.query.filter_by(active=True).all()
    return render_template("select_event.html", events=events)


@app.route('/select_event/<int:event_id>')
def select_event(event_id):
    event = Event.query.filter_by(id=event_id, active=True).first()
    if not event:
        return render_template("message.html", message="Évènement invalide ou inactif.")
    session['event_id'] = event.id
    return redirect(url_for('home'))


@app.route('/')
def home():
    event = get_current_event()
    if not event:
        return redirect(url_for('index'))
    
    today = datetime.now(PARIS_TZ).date()
    compteur = CompteurEmails.query.filter_by(date=today).first()
    emails_depasses = compteur and compteur.count >= MAX_EMAILS

    after_date = today >= event.date
    date_str = event.date.strftime('%d/%m/%Y')
    return render_template(
        'index.html',
        evenement=event.name,
        date=date_str,
        event_active = event.active,
        after_date=after_date,
        emails_depasses=emails_depasses,
        recaptcha_sitekey=None if not CAPTCHA else app.config['RECAPTCHA_SITE_KEY']
    )


@app.route('/cancel', methods=['POST'])
@limiter.limit("20/day;10/hour;3/minute")
def cancel_request():
    event = get_current_event()
    if not event:
        return redirect(url_for('index'))

    today = datetime.now(PARIS_TZ).date()
    if today >= event.date:
        return render_template("message.html", message=f"La date limite ({date_str}) est dépassée. Les annulations et inscriptions sur la liste d'attente pour le {date_str} sont désormais impossibles.", prenom="")
    
    if not event.active:
        return render_template("message.html", message=f"Les annulations et inscriptions sur la liste d'attente pour le {event.name} ont été fermées par l'organisateur.", prenom="")
    
    email = request.form['email']

    if CAPTCHA:
        # HONEYPOT : champ caché rempli → bot probable
        if request.form.get('nickname'):
            return render_template("message.html", message="Formulaire rejeté (bot détecté).")

        # reCAPTCHA : vérification du token
        captcha_token = request.form.get("g-recaptcha-response")
        if not captcha_token or not verify_captcha(captcha_token):
            return render_template("message.html", message="Échec de la vérification CAPTCHA.")

    user = Utilisateur.query.filter_by(email=email, event_id=event.id).first()
    participant = Participant.query.filter_by(utilisateur_id=user.id).first() if user else None
    if not participant:
        return render_template("message.html", prenom="", message=f"Vous n'êtes pas inscrit au {event.name}.")

    token = token_serializer.dumps({'email': email, 'event_id': event.id, 'action': 'cancel'})
    confirm_url = url_for('confirm_action', token=token, _external=True)

    # Envoi du mail
    prenom = user.prenom if user else ""
    sujet = f"Confirmation de l'annulation de votre partipation au {event.name}"
    corps = f"""
        <p>Bonjour {prenom},</p>
        <p>Veuillez confirmer l'annulation de votre participation au {event.name} en cliquant sur le lien suivant :</p>
        <p><a href="{confirm_url}">{confirm_url}</a></p>
        <p>Bien cordialement,<br>L’équipe du {EQUIPE}.</p>
    """
    if EMAIL:
        send_email(email, sujet, corps)
    print(f"Lien de confirmation cancel_request pour {email} : {confirm_url}")
    return render_template("message.html", message=f"Un email de confirmation a été envoyé à {email}.", prenom=prenom)


@app.route('/waitlist', methods=['POST'])
@limiter.limit("20/day;10/hour;3/minute")
def waitlist_request():
    event = get_current_event()
    if not event:
        return redirect(url_for('index'))
    
    today = datetime.now(PARIS_TZ).date()
    if today >= event.date:
        return render_template("message.html", message=f"La date limite ({date_str}) est dépassée. Les annulations et inscriptions sur la liste d'attente pour le {date_str} sont désormais impossibles.", prenom="")
    
    if not event.active:
        return render_template("message.html", message=f"Les annulations et inscriptions sur la liste d'attente pour le {event.name} ont été fermées par l'organisateur.", prenom="")

    email = request.form['email']

    if CAPTCHA:
        # HONEYPOT : champ caché rempli → bot probable
        if request.form.get('nickname'):
            return render_template("message.html", message="Formulaire rejeté (bot détecté).")

        # reCAPTCHA : vérification du token
        captcha_token = request.form.get("g-recaptcha-response")
        if not captcha_token or not verify_captcha(captcha_token):
            return render_template("message.html", message="Échec de la vérification CAPTCHA.")

    user = Utilisateur.query.filter_by(email=email, event_id=event.id).first()
    if user:
        participant = Participant.query.filter_by(utilisateur_id=user.id).first()
        attente = Attente.query.filter_by(utilisateur_id=user.id).first()
        if participant:
            return render_template("message.html", prenom=user.prenom, message=f"Vous êtes déjà inscrit au {event.name}.")
        if attente:
            return render_template("message.html", prenom=user.prenom, message=f"Vous êtes déjà sur la liste d'attente du {event.name}.")

    token = token_serializer.dumps({'email': email, 'event_id': event.id, 'action': 'waitlist'})
    confirm_url = url_for('confirm_action', token=token, _external=True)

    # Envoi du mail
    prenom = user.prenom if user else ""
    sujet = f"Confirmation d'inscription à la liste d'attente du {event.name}"
    corps = f"""
        <p>Bonjour {prenom},</p>
        <p>Veuillez confirmer votre inscription à la liste d'attente du {event.name} en cliquant sur le lien suivant :</p>
        <p><a href="{confirm_url}">{confirm_url}</a></p>
        <p>Bien cordialement,<br>L’équipe du {EQUIPE}.</p>
    """
    if EMAIL:
        send_email(email, sujet, corps)
    print(f"Lien de confirmation waitlist_request pour {email}: {confirm_url}")
    return render_template("message.html", message=f"Un email de confirmation a été envoyé à {email}", prenom=prenom)


@app.route('/profil/<token>', methods=['GET', 'POST'])
def profil_form(token):
    try:
        data = token_serializer.loads(token, max_age=app.config['SECURITY_TOKEN_MAX_AGE'])
        email = data.get('email')
        event_id = data.get('event_id')
    except Exception:
        return render_template("message.html", message="Lien invalide ou expiré.", prenom=""), 400

    user = Utilisateur.query.filter_by(email=email, event_id=event_id).first()
    if not user:
        return render_template("message.html", message="Utilisateur non trouvé.", prenom=""), 404

    event = Event.query.filter_by(id=event_id).first()
    if not event:
        return render_template("message.html", message="Évènement non trouvé.", prenom=""), 404 
    
    if request.method == 'POST':
        token_post = request.form.get('token')
        try:
            data_post = token_serializer.loads(token_post, max_age=app.config['SECURITY_TOKEN_MAX_AGE'])
            email_post = data_post.get('email')
            if email_post != email:
                return render_template("message.html", message="Token invalide.", prenom=""), 400
        except Exception:
            return render_template("message.html", message="Token invalide ou expiré.", prenom=""), 400

        user.prenom = request.form['prenom']
        user.nom = request.form['nom']
        db.session.commit()
        
        return render_template("message.html", message=f"Merci, vos informations personnelles ont bien été enregistrées.", prenom=user.prenom)
    
    return render_template('profil_form.html',
                           email=email,
                           prenom=user.prenom or "",
                           nom=user.nom or "",
                           evenement=event.name,
                           token=token)


@app.route('/statut_direct', methods=['POST'])
@limiter.limit("20/day;10/hour;3/minute")
def statut_direct():
    event = get_current_event()
    if not event:
        return redirect(url_for('index'))
    
    if not event.active:
        return render_template("message.html", message=f"Les annulations et inscriptions sur la liste d'attente pour le {event.name} ont été fermées par l'organisateur.", prenom="")

    if CAPTCHA:
        # HONEYPOT : champ caché rempli → bot probable
        if request.form.get('nickname'):
            return render_template("message.html", message="Formulaire rejeté (bot détecté).")

        # reCAPTCHA : vérification du token
        captcha_token = request.form.get("g-recaptcha-response")
        if not captcha_token or not verify_captcha(captcha_token):
            return render_template("message.html", message="Échec de la vérification CAPTCHA.")
    
    email = request.form['email']
    user = Utilisateur.query.filter_by(email=email, event_id=event.id).first()
    if not user:
        return render_template("message.html", prenom="", message=f"Aucun compte associé à {email}.")

    participant = Participant.query.filter_by(utilisateur_id=user.id).first()
    attente = Attente.query.filter_by(utilisateur_id=user.id).first()

    if participant:
        if user.paid:
            statut = f"Vous êtes actuellement inscrit au {event.name} et votre paiement a bien été reçu."
        else:
            statut = f"Vous êtes inscrit au {event.name} mais vous n'avez pas encore effectué votre paiement. Celui-ci sera à effectuer sur place le jour de l'évènement."
    elif attente:
        ahead = Attente.query.join(Utilisateur).filter(
            Attente.inscription_date < attente.inscription_date,
            Attente.contacted == False,
            Utilisateur.event_id == event.id,
        ).count()
        statut = f"Vous êtes sur la liste d’attente du {event.name} avec {ahead} personne(s) devant vous."
    else:
        if user.paid:
            statut = f"Vous avez réglé votre participation mais vous n’êtes actuellement pas inscrit au {event.name}. Un remboursement vous sera effectué après la tenue de l'évènement."
        else:
            statut = f"Vous n’êtes actuellement ni inscrit ni sur la liste d’attente du {event.name}."

    return render_template("message.html", prenom=user.prenom or "", message=statut)


@app.route('/confirm/<token>')
def confirm_action(token):
    try:
        data = token_serializer.loads(token, max_age=app.config['SECURITY_TOKEN_MAX_AGE'])
        email = data['email']
        event_id = data['event_id']
        action = data['action']
    except Exception:
        return render_template("message.html", message="Lien invalide ou expiré.", prenom="")

    user = Utilisateur.query.filter_by(email=email, event_id=event_id).first()
    prenom = user.prenom if user else ""

    event = Event.query.filter_by(id=event_id).first()
    if not event:
        return render_template("message.html", message="Évènement non trouvé.", prenom=""), 404
    date_str = event.date.strftime('%d/%m/%Y')
        
    today = datetime.now(PARIS_TZ).date()
    if today >= event.date:
        return render_template("message.html", message=f"La date limite ({date_str}) est dépassée. Les annulations et inscriptions sur la liste d'attente pour le {date_str} sont désormais impossibles.", prenom=prenom)

    if not event.active:
        return render_template("message.html", message=f"Les annulations et inscriptions sur la liste d'attente pour le {event.name} ont été fermées par l'organisateur.", prenom=prenom)
    
    if action == 'cancel':
        if not user:
            return render_template("message.html", message="Utilisateur non trouvé.", prenom="")   
        p = Participant.query.filter_by(utilisateur_id=user.id).first()
        if p:
            db.session.delete(p)
            compteur = PlacesLiberees.query.filter_by(event_id=event_id).first()
            if not compteur:
                compteur = PlacesLiberees(event_id=event.id, compteur=1)
                db.session.add(compteur)
            else:
                compteur.compteur += 1
            db.session.commit()
            return render_template("message.html", message=f"Votre participation au {event.name} a été annulée. Un remboursement vous sera effectué après la tenue de l'évènement.", prenom=prenom)
        else:
            return render_template("message.html", message=f"Vous n'étiez pas inscrit au {event.name}.", prenom=prenom)

    elif action == 'waitlist':
        if user:
            if Participant.query.filter_by(utilisateur_id=user.id).first():
                return render_template("message.html", message=f"Vous êtes déjà inscrit au {event.name}.", prenom=prenom)

            if Attente.query.filter_by(utilisateur_id=user.id).first():
                return render_template("message.html", message=f"Vous êtes déjà sur la liste d'attente du {event.name}.", prenom=prenom)

        if not user:
            db.session.add(Utilisateur(email=email, event_id=event_id, paid=False))
            db.session.commit()
            user = Utilisateur.query.filter_by(email=email, event_id=event_id).first()
            
        db.session.add(Attente(utilisateur_id=user.id))
        db.session.commit()

        token = token_serializer.dumps({'email': email, 'event_id': event_id})
        return redirect(url_for('profil_form', token=token))
    
    elif action == 'accept':
        if not user:
            return render_template("message.html", message="Utilisateur non trouvé.", prenom="")   
        notif = Notification.query.filter_by(utilisateur_id=user.id, status=NotificationStatus.PENDING.value).first()
        
        if notif:
            notif_time = notif.expires_at
            if notif_time.tzinfo is None:
                notif_time = utc.localize(notif_time)

            notif_time = notif_time.astimezone(PARIS_TZ)

            if datetime.now(PARIS_TZ) < notif_time:
                if not Participant.query.filter_by(utilisateur_id=user.id).first():
                    db.session.add(Participant(utilisateur_id=user.id))
                    Attente.query.filter_by(utilisateur_id=user.id).delete()
                    notif.status = NotificationStatus.RESPONDED.value
                    notif.processed_at = datetime.now(PARIS_TZ)
                    db.session.commit()
                    return render_template("message.html", message=f"Félicitations, vous avez maintenant une place pour le {event.name} !", prenom=user.prenom)
                return render_template("message.html", message=f"Vous êtes déjà inscrit au {event.name}.", prenom=prenom)

        return render_template("message.html", message="Lien expiré ou déjà utilisé.", prenom=prenom)

    return render_template("message.html", message="Action impossible.", prenom=prenom)


@app.route('/admin')
@requires_auth
def admin_panel():
    events = Event.query.all()
    today = datetime.now(PARIS_TZ).date()
    return render_template("admin.html", events=events, today=today)

    
@app.route('/init_participants', methods=['POST'])
@requires_auth
def init_participants():
    name = request.form.get('nom_evenement')
    date_str = request.form.get('date_evenement')
    file = request.files.get('csvfile')
    selected_tarifs = request.form.getlist('tarifs')

    if not name or not date_str or not file or file.filename == '':
        return render_template("message.html", prenom="", message="Les 3 champs (nom, date, fichier CSV) sont obligatoires.")

    try:
        date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return render_template("message.html", prenom="", message="Date invalide.")

    try:
        event_exist = Event.query.filter_by(name=name).first()
        if event_exist:
            return render_template("message.html", prenom="", message=f"L'évènement \"{name}\" existe déjà.")

        stream = io.StringIO(file.stream.read().decode("utf-8-sig"))
        reader = csv.DictReader(stream, delimiter=';')
        
        fieldnames = set(reader.fieldnames)
        lower_fieldnames = {name.lower(): name for name in fieldnames}

        # Colonne Statut
        has_statut = 'statut de la commande'.lower() in lower_fieldnames
        
        # Colonne tarif
        has_tarif = 'tarif'.lower() in lower_fieldnames
        
        # Prénom
        prenom_col = (
            lower_fieldnames.get('prénom participant'.lower())
            or lower_fieldnames.get('prénom'.lower())
        )
        # Nom
        nom_col = (
            lower_fieldnames.get('nom participant'.lower())
            or lower_fieldnames.get('nom'.lower())
        )
        # Colonnes email
        email_col = next(
            (original_name for lower_name, original_name in lower_fieldnames.items()
             if lower_name.startswith("adresse mail de contact")),
            lower_fieldnames.get("email")
        )

        
        if not prenom_col or not nom_col or not email_col:
            return render_template("message.html", prenom="", message="Le fichier CSV doit contenir au moins les colonnes prénom, nom et email.")

        # Si pas de colonne Tarif, on simule un tarif unique
        if not has_tarif:
            tarifs_possibles = ['Tarif unique']
        else:
            tarifs_possibles = selected_tarifs

        
        event = Event(name=name, date=date)
        db.session.add(event)
        db.session.commit()
        
        count = 0
        utilisateurs_to_add = []
        
        for row in reader:
            # Filtrage statut
            if has_statut:
                statut = row.get('Statut de la commande', '').strip().lower()
                if statut != 'validé':
                    continue

            # Tarifs
            tarif = row.get('Tarif', 'Tarif unique').strip() if has_tarif else 'Tarif unique'
            if tarif not in tarifs_possibles:
                continue

            # Récupération données
            prenom = row.get(prenom_col, '').strip()
            nom = row.get(nom_col, '').strip()
            email = row.get(email_col, '').strip()

            if not email:
                continue

            if not any(u.email == email for u in utilisateurs_to_add):
                user = Utilisateur(email=email, event_id=event.id, prenom=prenom, nom=nom, paid=True)
                utilisateurs_to_add.append(user)
                count += 1

        # Insertion en batch
        db.session.add_all(utilisateurs_to_add)
        db.session.commit()

        # Création des participants après avoir les IDs
        
        participants_to_add = []
        for user in utilisateurs_to_add:
            participant = Participant(utilisateur_id=user.id)
            participants_to_add.append(participant)

        db.session.add_all(participants_to_add)
        db.session.commit()

        print("L'évènement \"{event.name}\" a été créé avec {count} participants.")

        return redirect(url_for('admin_panel'))


    except Exception as e:
        db.session.rollback()
        return render_template("message.html", prenom="", message=f"Erreur lors de l'import : {e}")



@app.route('/admin/toggle_event_status', methods=['POST'])
@requires_auth
def toggle_event_status():
    event_name = request.form['event_name']
    event = Event.query.filter_by(name=event_name).first()

    if event:
        event.active = not event.active
        db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/delete_event/<int:event_id>', methods=['POST'])
@requires_auth
def delete_event(event_id):
    today = datetime.now(PARIS_TZ).date()
    
    event = Event.query.get(event_id)
    if not event:
        return render_template("message.html", message="Événement introuvable.")

    if event.active or event.date >= today:
        return render_template("message.html", message="Impossible de supprimer un évènement actif ou avant la date de l'évènement.")

    # Suppression directe SQL (sans charger les objets en mémoire)
    db.session.execute(text("""
        DELETE FROM participant WHERE utilisateur_id IN (SELECT id FROM utilisateur WHERE event_id = :eid);
    """), {'eid': event_id})

    db.session.execute(text("""
        DELETE FROM notification WHERE utilisateur_id IN (SELECT id FROM utilisateur WHERE event_id = :eid);
    """), {'eid': event_id})

    db.session.execute(text("""
        DELETE FROM attente WHERE utilisateur_id IN (SELECT id FROM utilisateur WHERE event_id = :eid);
    """), {'eid': event_id})

    db.session.execute(text("""
        DELETE FROM utilisateur WHERE event_id = :eid;
    """), {'eid': event_id})

    db.session.execute(text("""
        DELETE FROM places_liberees WHERE event_id = :eid;
    """), {'eid': event_id})

    db.session.execute(text("""
        DELETE FROM event WHERE id = :eid;
    """), {'eid': event_id})

    db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/export_zip', methods=['POST'])
@requires_auth
def export_zip():
    name = request.form.get("nom_evenement")
    if not name:
        return render_template("message.html", prenom="", message="Le champ nom est obligatoire.")

    event = Event.query.filter_by(name=name).first()
    if not event:
        return render_template("message.html", prenom="", message=f"L'évènement \"{name}\" n'existe pas.") 
    try:
        export_csv(event.id)
        zip_file = sorted(
            [f for f in os.listdir('exports') if f.endswith('.zip')],
            reverse=True
        )[0]
        return send_from_directory('exports', zip_file, as_attachment=True)
    except Exception as e:
        return f"Erreur lors de l'exportation : {str(e)}", 500



# --- NOTIFICATION SUIVANT ET CRON ---

def notify_next(event_id):
    event = Event.query.filter_by(id=event_id).first()
    compteur = PlacesLiberees.query.filter_by(event_id=event_id).first()
    if not compteur or compteur.compteur <= 0:
        return

    next_waiting = (
        Attente.query
        .join(Utilisateur)
        .filter(
            Utilisateur.event_id == event.id,
            Attente.contacted == False
        )
        .order_by(Attente.inscription_date)
        .first()
    )

    if next_waiting:
        next_waiting.contacted = True
        user = Utilisateur.query.filter_by(id=next_waiting.utilisateur_id).first()
        token = token_serializer.dumps({'email': user.email, 'event_id': event_id, 'action': 'accept'})
        confirm_url = url_for('confirm_action', token=token, _external=True)
        expiration = datetime.now(PARIS_TZ) + timedelta(seconds=waiting_time(event_id))
        max_date = PARIS_TZ.localize(datetime.combine(event.date, datetime.min.time()))
        expiration = min(expiration, max_date)
        
        n = Notification(
            utilisateur_id=user.id,
            status=NotificationStatus.PENDING.value,
            expires_at=expiration
        )
        db.session.add(n)


        compteur.compteur -= 1
        db.session.commit()

        # Envoi du mail
        expiration_str = expiration.strftime("%d/%m/%Y à %Hh%M (heure de Paris)")
        sujet = f"Une place s'est libérée pour le {event.name} !"
        corps = f"""
            <p>Bonjour {user.prenom},</p>
            <p>Veuillez confirmer votre participation au {event.name} avant le <strong>{expiration_str}</strong>. En cliquant sur le lien suivant, <strong>vous vous engagez à payer votre place</strong> le jour de l'évènement :</p>
            <p><a href="{confirm_url}">{confirm_url}</a></p>
            <p>Bien cordialement,<br>L’équipe du {EQUIPE}.</p>
        """
        if EMAIL:
            send_email(user.email, sujet, corps)
        print(f"Lien de confirmation notify_next pour {user.email} avant le {expiration_str}: {confirm_url}")
    else:
        print("Aucune autre personne en attente à notifier.")
        

def run_check_expirations():
    events = Event.query.filter_by(active=True).all()
    for event in events:
        now = datetime.now(tz=PARIS_TZ)
        date_str = event.date.strftime('%d/%m/%Y')
        
        if now.date() >= event.date:
            print(f"La date limite ({date_str}) est dépassée. L'envoi d'emails aux personnes sur la liste d'attente est terminé.")
            
        else:
            notifications = (
                Notification.query
                .join(Utilisateur)
                .filter(Utilisateur.event_id == event.id, Notification.status == NotificationStatus.PENDING.value)
                .all()
            )
            
            for notif in notifications:
                user = Utilisateur.query.filter_by(id=notif.utilisateur_id).first()
                
                notif_time = notif.expires_at
                if notif_time.tzinfo is None:
                    notif_time = utc.localize(notif_time)

                notif_time = notif_time.astimezone(PARIS_TZ)

                if now > notif_time:
                    print(f"Notification expirée pour {user.email}")

                    attente = Attente.query.filter_by(utilisateur_id=user.id).first()
                    if attente:
                        db.session.delete(attente)
                        print(f"{user.email} supprimé de la liste d'attente")
                        expiration_str = notif_time.strftime("%d/%m/%Y à %Hh%M (heure de Paris)")

                        sujet = f"La place pour le {event.name} n'est plus disponible"
                        corps = f"""
                            <p>Bonjour {user.prenom},</p>
                            <p>La date d'expiration ({expiration_str}) étant dépassée, vous avez été retiré de la liste d'attente du {event.name} et la place disponible a été proposée à la personne suivante sur la liste d'attente.</p>
                            <p>Si vous souhaitez néanmoins toujours participer au {event.name}, il faudra vous réinscrire sur la liste d'attente.</p>
                            <p>Bien cordialement,<br>L’équipe du {EQUIPE}.</p>
                        """
                        if EMAIL:
                            send_email(user.email, sujet, corps)

                    # Au lieu de supprimer la notif, on marque comme expirée
                    notif.status = NotificationStatus.EXPIRED.value
                    notif.processed_at = now

                    compteur = PlacesLiberees.query.filter_by(event_id=event.id).first()
                    if not compteur:
                        compteur = PlacesLiberees(event_id=event.id, compteur=1)
                        db.session.add(compteur)
                    else:
                        compteur.compteur += 1

                    db.session.commit()

            notify_next(event.id)


@limiter.limit("2/minute")
@app.route("/cron/check_expirations")
def cron_check_expirations():
    token = request.args.get("token")
    if token != CRON_SECRET:
        abort(403)

    run_check_expirations()
    return "OK", 200


# --- TEST MAILS OVERLOAD ---


@app.route('/test-mails', methods=['GET'])
@requires_auth
def test_send_mails():
    if not LOCAL_TEST:
        abort(403, description="Cette route de test est désactivée en production.")

    N_MAILS = 30
    test_email = os.getenv("GMAIL")
   
    for i in range(N_MAILS):
        sujet = f"[Test {i+1}/{N_MAILS}]"
        corps = f"""
            <p>Bonjour,</p>
            <p>Ceci est le message de test numéro {i+1}.</p>
            <p>Bien cordialement,<br>L’équipe du {EQUIPE}.</p>
        """

        if EMAIL:
            send_email(test_email, sujet, corps)
        print(f"[Test {i+1}/{N_MAILS}] Email envoyé à {test_email}")

    return render_template("message.html", message=f"{N_MAILS} emails de test ont été envoyés avec succès.", prenom="")


# --- INIT ---

@app.before_request
def create_tables():
    app.before_request_funcs[None].remove(create_tables)
    db.create_all()


@app.before_request
def make_session_permanent():
    session.permanent = True


# --- LOG ---

@app.before_request
def log_all_requests():
    excluded_routes = ['/', '/select', '/cron/check_expirations', '/favicon.ico'] + [f"/select_event/{i}" for i in range(100)]
    token_routes = ['/profil/', '/confirm/']
    
    if request.path in excluded_routes:
        return

    path = request.path
    email = None
    action = ''

    for prefix in token_routes:
        if path.startswith(prefix):
            # Extract token from the URL
            token = path[len(prefix):]
            token = unquote(token)
            try:
                data = token_serializer.loads(token, max_age=app.config['SECURITY_TOKEN_MAX_AGE'])
                email = data.get('email', 'unknown')
                action = data.get('action', '')
            except Exception as e:
                email = f"invalid-token: {e}"
                action = 'invalid'

            path = prefix + action
            break
    
    if not email:
        email = request.form.get('email', 'unknown')
    
    ip = get_client_ip()
    log = Logs(endpoint=path, ip=ip, email=email)
    db.session.add(log)
    db.session.commit()


# --- EXEC (DEV ONLY) ---

if __name__ == '__main__':
    app.run(debug=True)
