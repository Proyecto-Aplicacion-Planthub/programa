import base64
from flask import Flask, render_template, Response, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import mediapipe as mp
import cv2
import math
import numpy as np
import os
import pyotp
import qrcode
from io import BytesIO

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://lindell2_SQLLogin_2:ztg92qokn7@Usuarios1.mssql.somee.com/Usuarios1?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'user123'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    permissions = db.Column(db.String(255), nullable=True)
    profile_image = db.Column(db.LargeBinary)
    totp_secret = db.Column(db.String(16), nullable=True)  # Clave secreta para TOTP

    def is_admin(self):
        return self.role == 'admin'

# Configuración de Mediapipe para la malla facial
mp_face_mesh = mp.solutions.face_mesh
mp_drawing = mp.solutions.drawing_utils
mp_drawing_styles = mp.solutions.drawing_styles

# Inicializar captura de video
cap = cv2.VideoCapture(0)

# Función para contar parpadeos y capturar imágenes
def generate_frames(username):
    blink_count = 0
    blink_detected = False
    clean_image = None  # Para guardar la imagen sin malla ni contador

    with mp_face_mesh.FaceMesh(max_num_faces=1, refine_landmarks=True, min_detection_confidence=0.5, min_tracking_confidence=0.5) as face_mesh:
        try:
            while True:
                success, frame = cap.read()
                if not success:
                    print("No se pudo capturar el frame.")
                    break

                clean_image = frame.copy()

                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                results = face_mesh.process(frame_rgb)

                if results.multi_face_landmarks:
                    for face_landmarks in results.multi_face_landmarks:
                        mp_drawing.draw_landmarks(
                            image=frame,
                            landmark_list=face_landmarks,
                            connections=mp_face_mesh.FACEMESH_TESSELATION,
                            landmark_drawing_spec=None,
                            connection_drawing_spec=mp_drawing_styles.get_default_face_mesh_tesselation_style()
                        )

                        landmarks = [(int(point.x * frame.shape[1]), int(point.y * frame.shape[0])) for point in face_landmarks.landmark]

                        eye_right = landmarks[145], landmarks[159]
                        dist_right_eye = math.hypot(eye_right[0][0] - eye_right[1][0], eye_right[0][1] - eye_right[1][1])

                        eye_left = landmarks[374], landmarks[386]
                        dist_left_eye = math.hypot(eye_left[0][0] - eye_left[1][0], eye_left[0][1] - eye_left[1][1])

                        if dist_right_eye < 10 and dist_left_eye < 10 and not blink_detected:
                            blink_count += 1
                            blink_detected = True
                        elif dist_right_eye > 10 and dist_left_eye > 10:
                            blink_detected = False

                        cv2.putText(frame, f"Parpadeos: {blink_count}", (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 0, 0), 2)

                        if blink_count >= 3:
                            _, buffer = cv2.imencode('.jpg', clean_image)
                            img_base64 = base64.b64encode(buffer).decode('utf-8')
                            return img_base64

                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                    b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        finally:
            if cap.isOpened():
                cap.release()

# Ruta para transmitir el video en tiempo real
@app.route('/video_feed')
@login_required
def video_feed():
    return Response(generate_frames(current_user.username), mimetype='multipart/x-mixed-replace; boundary=frame')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('No tienes permiso para acceder a esta página.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def coadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'coadmin']:
            flash('No tienes permiso para acceder a esta página.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        permissions = request.form.getlist('permissions')
        profile_image = request.form['profile_image']

        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya está en uso. Elige otro.')
            return redirect(url_for('create_user'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role, permissions=",".join(permissions))

        # Si es administrador, generar la clave TOTP
        if new_user.is_admin():
            new_user.totp_secret = pyotp.random_base32()

        # Si hay una imagen de perfil, convertirla de base64 a binario
        if profile_image:
            profile_image_data = profile_image.split(',')[1]
            new_user.profile_image = base64.b64decode(profile_image_data)
            image_filename = f'{username}.jpg'
            image_path = os.path.join('static/faces', image_filename)
            with open(image_path, 'wb') as img_file:
                img_file.write(base64.b64decode(profile_image_data))

        # Guardar el usuario en la base de datos
        db.session.add(new_user)
        db.session.commit()

        # Si el usuario es un administrador, redirigir para mostrar el código QR de TOTP
        if new_user.is_admin():
            flash('Por favor, escanea este código QR con tu aplicación de autenticación para configurar TOTP.', 'info')
            return redirect(url_for('show_totp_qr', user_id=new_user.id))

        flash('Usuario creado correctamente.')
        return redirect(url_for('index'))

    return render_template('create_user.html')

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
@coadmin_required
def edit_user(username):
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        user.role = request.form['role']
        user.permissions = ",".join(request.form.getlist('permissions'))

        db.session.commit()
        flash('Usuario actualizado correctamente.')
        return redirect(url_for('index'))

    return render_template('edit_user.html', user=user)

# Agregar aquí la función update_user
@app.route('/update_user', methods=['POST'])
@login_required
@coadmin_required
def update_user():
    username = request.form['username']
    new_username = request.form['new_username']
    password = request.form['password']
    role = request.form['role']
    reset_totp = 'reset_totp' in request.form  # Verifica si se seleccionó la opción de restablecer TOTP

    user = User.query.filter_by(username=username).first()

    if user:
        user.username = new_username
        if password:
            user.password = generate_password_hash(password)
        user.role = role

        # Restablecer la configuración de TOTP si se seleccionó la opción
        if reset_totp:
            user.totp_secret = pyotp.random_base32()
            flash('La autenticación TOTP ha sido restablecida. Por favor, configura el TOTP nuevamente.', 'info')

        db.session.commit()
        flash('Usuario actualizado correctamente.')
    else:
        flash('Usuario no encontrado.')

    return redirect(url_for('index'))

@app.route('/delete_user/<username>', methods=['DELETE'])
@login_required
@admin_required
def delete_user_route(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Usuario eliminado correctamente.')
    else:
        flash('El usuario no se encontró.')
    return '', 204

@app.route('/totp_qr/<int:user_id>')
def show_totp_qr(user_id):
    user = User.query.get(user_id)
    if not user or not user.is_admin() or not user.totp_secret:
        flash('Usuario no encontrado o no es administrador.', 'error')
        return redirect(url_for('index'))

    # Generar la URL de autenticación para la aplicación TOTP
    totp_uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
        user.username, issuer_name="My Flask App"
    )

    # Generar el código QR
    img = qrcode.make(totp_uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype="image/png")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.is_admin():
                login_user(user)
                flash('Autenticación TOTP requerida.', 'info')
                return redirect(url_for('verify_totp'))
            login_user(user)
            flash('Inicio de sesión exitoso.')
            return redirect(url_for('index'))
        else:
            flash('Credenciales inválidas.')
    return render_template('login.html')

@app.route('/verify_totp', methods=['GET', 'POST'])
@login_required
def verify_totp():
    if request.method == 'POST':
        totp_code = request.form['totp']
        totp = pyotp.TOTP(current_user.totp_secret)

        if not totp.verify(totp_code):
            flash('Código TOTP incorrecto.', 'error')
            return redirect(url_for('verify_totp'))

        flash('Autenticación TOTP exitosa.', 'success')
        return redirect(url_for('index'))

    return render_template('verify_totp.html')

@app.route('/logout')
@login_required
def logout():
    global cap
    if cap.isOpened():
        cap.release()
    logout_user()
    flash('Has cerrado sesión correctamente.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)





