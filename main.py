from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, session, jsonify
from log_class import UserInfo
from app_config import *
from host_settings import *
import hashlib
from tables import app, m883lfs, Users, Uploads, MacAdrs, MontyHallGames
from login_required import *
from datetime import datetime
import random
from passcontrol import is_password_valid
from device_scanner import NetworkScanner 
from admin_required import *
import matplotlib.pyplot as plt
import io
import base64
import os
import socket
from werkzeug.utils import secure_filename

""" Hostname """
try:
    system_username = UserInfo().get_system_username().lower()
except:
    system_username = "marduk883"

@app.before_request
def check_blocked_mac():
    """
    This function is executed before each request to check if the client's MAC address is blocked.
    It retrieves the client's IP address, then the MAC address associated with that IP.
    If the MAC address is found in the blocked list, the request is aborted with a 403 error.
    """
    user_info = UserInfo()
    ip_address = request.remote_addr # Get the IP address of the client making the request
    mac_address = user_info.get_mac(ip_address) # Retrieve the MAC address associated with the IP address
    
    if mac_address != "Unknown MAC Address":
        blocked_device = MacAdrs.query.filter_by(mac_adrs=mac_address, is_locked=True).first() # Check if the MAC address is in the blocked list
        if blocked_device:
            return "Bu cihaz engellenmiştir!", 403 # Abort the request with a 403 error if the device is blocked


@app.route('/')
def index():
    """
    This route handles the home page.
    It logs user information and renders the index.html template.
    """
    # Log all information when the home page is accessed
    user_info = UserInfo()
    ip_address = user_info.get_ip()
    login_time = user_info.get_login_date()
    device_type = user_info.get_platform_info()
    if ip_address == "Unknown IP Address" and login_time == "Unknown Time" and device_type == "Unknown Platform":
        user_info.log_critical_if_all_unknown()
    return render_template('index.html', system_username=system_username)

@app.route('/serversettings', methods=['GET', 'POST'])
@login_required
@admin_required
def serversettings():
    """
    This route handles the server settings page, allowing network scanning and MAC address blocking.
    It requires the user to be logged in and have admin privileges.
    """
    scan_results = None
    host_ip = socket.gethostbyname(socket.gethostname())  # Get Host IP address
    scan_type = None  # define scan_type variable
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')

        scanner = NetworkScanner()
        scan_results = scanner.scan()

        # Save MAC addresses to the database
        for device in scan_results:
            mac_address = device.get('mac')  # Get MAC address
            if mac_address:
                existing_mac = MacAdrs.query.filter_by(mac_adrs=mac_address).first()
                if not existing_mac:
                    new_mac = MacAdrs(mac_adrs=mac_address, is_locked=False)
                    m883lfs.session.add(new_mac)
                    m883lfs.session.commit()

        # Saving the results to a JSON file (optional)
        # scanner.save_results(scan_results, scan_type)
    
    # Get blocked MAC addresses
    blocked_mac_addresses = [mac.mac_adrs for mac in MacAdrs.query.filter_by(is_locked=True).all()]

    return render_template("serversettings.html", scan_results=scan_results, scan_type=scan_type, host_ip=host_ip, blocked_mac_addresses=blocked_mac_addresses)

@app.route('/block_device/<mac>', methods=['POST'])
@login_required
@admin_required
def block_device(mac):
    """
    This route blocks a device by its MAC address.
    It requires the user to be logged in and have admin privileges.
    """
    mac_address = MacAdrs.query.filter_by(mac_adrs=mac).first()
    if mac_address:
        mac_address.is_locked = True
        m883lfs.session.commit()
        return jsonify({'message': 'Device blocked successfully.'}), 200
    else:
        return jsonify({'message': 'Device not found.'}), 404

@app.route('/unblock_device/<mac>', methods=['POST'])
@login_required
@admin_required
def unblock_device(mac):
    """
    This route unblocks a device by its MAC address.
    It requires the user to be logged in and have admin privileges.
    """
    mac_address = MacAdrs.query.filter_by(mac_adrs=mac).first()
    if mac_address:
        mac_address.is_locked = False
        m883lfs.session.commit()
        return jsonify({'message': 'Device unblocked successfully.'}), 200
    else:
        return jsonify({'message': 'Device not found.'}), 404



@app.route('/montyhall', methods=['GET', 'POST'])
@login_required
def montyhall():
    """
    This route handles the Monty Hall game.
    It uses session variables to maintain the game state.
    """
    if 'montyhall_game' not in session:
        session['montyhall_game'] = {}

    if request.method == 'POST':
        if 'initial_choice' in request.form:
            doors = [1, 2, 3]
            car = random.choice(doors)
            first_choice = int(request.form['initial_choice'])
            goat_doors = [door for door in doors if door != car]
            if first_choice == car:
                revealed_door = random.choice(goat_doors)
            else:
                revealed_door = [door for door in goat_doors if door != first_choice][0]

            remaining_door = [door for door in doors if door != first_choice and door != revealed_door][0]

            session['montyhall_game'] = {
                'doors': doors,
                'car': car,
                'first_choice': first_choice,
                'revealed_door': revealed_door,
                'remaining_door': remaining_door
            }

            game_data = session['montyhall_game']
            return render_template('montyhall.html', game_data=game_data, step=2)

        else:
            # If there is no game data in the session, restart the game
            if not session.get('montyhall_game'):
                return redirect(url_for('montyhall'))

            doors = [1, 2, 3]
            car = session['montyhall_game']['car']
            first_choice = session['montyhall_game']['first_choice']
            revealed_door = session['montyhall_game']['revealed_door']
            remaining_door = session['montyhall_game']['remaining_door']
            switch = request.form.get('switch')

            if switch == 'yes':
                final_choice = remaining_door
            else:
                final_choice = first_choice

            win = final_choice == car

            # Save to database
            new_game = MontyHallGames(
                doors=str(doors),
                car=car,
                first_choice=first_choice,
                revealed_door=revealed_door,
                final_choice=final_choice,
                win=win,
                remaining_door=remaining_door,
                switch=switch
            )
            m883lfs.session.add(new_game)
            m883lfs.session.commit()

            # Calculate statistics
            switch_wins = MontyHallGames.query.filter_by(switch='yes', win=True).count()
            switch_losses = MontyHallGames.query.filter_by(switch='yes', win=False).count()
            stay_wins = MontyHallGames.query.filter_by(switch='no', win=True).count()
            stay_losses = MontyHallGames.query.filter_by(switch='no', win=False).count()

            # Create pie charts
            if switch_wins + switch_losses > 0:
                switch_pie_chart = create_pie_chart('Switch Choices', switch_wins, switch_losses)
            else:
                switch_pie_chart = None  # or a default chart

            if stay_wins + stay_losses > 0:
                stay_pie_chart = create_pie_chart('Stay Choices', stay_wins, stay_losses)
            else:
                stay_pie_chart = None  # or a default chart

            game_data = {
                'doors': doors,
                'car': car,
                'first_choice': first_choice,
                'revealed_door': revealed_door,
                'final_choice': final_choice,
                'win': win,
                'switch': switch,
                'switch_pie_chart': switch_pie_chart,
                'stay_pie_chart': stay_pie_chart
            }

            session.pop('montyhall_game', None)  # End the game and clear the session
            return render_template('montyhall.html', game_data=game_data, step=3)

    else:
        session.pop('montyhall_game', None)  # Start a new game and clear the session
        doors = [1, 2, 3]
        return render_template('montyhall.html', doors=doors, step=1)

def create_pie_chart(title, wins, losses):
    """
    This function creates a pie chart for the Monty Hall game statistics.
    It takes the title, number of wins, and number of losses as input.
    It returns the chart as a base64 encoded string.
    """
    labels = 'Wins', 'Losses'
    sizes = [wins, losses]
    colors = ['#888', '#ccc']  # Shades of black and white
    plt.figure(figsize=(50, 42))  # Increase chart size
    plt.rcParams['font.size'] = 150  # Increase font size
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 120})  # Increase percentage font size
    plt.title(title, fontsize=150)
    plt.axis('equal')  # Equal axes ensure that the pie is drawn as a circle.

    # Save chart data to a byte array
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()

    # Encode the byte array with base64
    return base64.b64encode(img.read()).decode('utf-8')

@app.errorhandler(404)
def page_not_found(e):
    """
    This route handles 404 errors (page not found).
    It renders the 404.html template.
    """
    return render_template('404.html'), 404

@app.route('/mainpage')
@login_required
def mainpage():
    """
    This route handles the main page.
    It requires the user to be logged in.
    """
    current_time = datetime.now().strftime('%H:%M:%S')  # 24-hour format
    return render_template('mainpage.html', current_time=current_time)

@app.route(f'/{system_username}_register_m883lfs', methods=['GET', 'POST'])
def register():
    """
    This route handles user registration.
    It checks if the username already exists and if the passwords match.
    It also validates the password strength.
    """
    if 'logged_in' in session and session['logged_in']:
        session['logged_in'] = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the username already exists
        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            flash(message="Username already exists!", category="danger")
        elif password != confirm_password:
            flash(message="Passwords do not match!", category="danger")
        elif not is_password_valid(password):
            flash("Password must be at least 10 characters long, contain at least one lowercase letter, one uppercase letter, one digit, and one special character.", "danger")
        else:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            new_user = Users(username=username, password=hashed_password, user_type="user", locked=False)
            m883lfs.session.add(new_user)
            m883lfs.session.commit()
            session['logged_in'] = True
            session['username'] = username
            session['user_type'] = new_user.user_type  # Add this line
            return redirect(url_for('server'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    This route handles user login.
    It checks the username and password against the database.
    It also handles account locking after too many failed login attempts.
    """
    current_time = datetime.now().strftime('%H:%M:%S')
    if 'logged_in' in session and session['logged_in']:
        session['logged_in'] = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        user = Users.query.filter_by(username=username).first()
        if user:
            if user.password == hashed_password:
                if user.locked:
                    flash(message="Your account has been locked due to too many failed login attempts.", category="danger")
                else:
                    user.failed_attempts = 0  # Reset failed attempts on successful login
                    session['logged_in'] = True
                    session['username'] = username
                    session['user_type'] = user.user_type
                    m883lfs.session.commit()  # Commit the changes to the database
                    return redirect(url_for('mainpage'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked = True
                    flash(message="Your account has been locked due to too many failed login attempts.", category="danger")
                else:
                    flash(message="Invalid credentials!", category="danger")
                m883lfs.session.commit()  # Commit the changes to the database
        else:
            flash(message="Invalid credentials!", category="danger")
    return render_template('login.html', session=session, system_username=system_username,current_time=current_time)

@app.route('/server', methods=['GET', 'POST'])
@login_required
def server():
    """
    This route handles the server file management page.
    It allows filtering files by extension, uploader, date, and filename.
    It requires the user to be logged in.
    """
    files = Uploads.query.all() 
    extensions = sorted(set(file.filename.split('.')[-1].lower() for file in files))
    usernames = sorted(set(file.uploaded_by for file in files))
    
    if request.method == 'POST':
        ext_filters = request.form.getlist('ext_filter')
        user_filters = request.form.getlist('user_filter')
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')
        filename_search = request.form.get('filename_search', '').lower()
        
        if ext_filters:
            files = [file for file in files if file.filename.split('.')[-1].lower() in ext_filters]
        if user_filters:
            files = [file for file in files if file.uploaded_by in user_filters]
        if date_from:
            date_from = datetime.strptime(date_from, '%Y-%m-%d')
            files = [file for file in files if file.upload_date >= date_from]
        if date_to:
            date_to = datetime.strptime(date_to, '%Y-%m-%d')
            files = [file for file in files if file.upload_date <= date_to]
        if filename_search:
            files = [file for file in files if filename_search in file.filename.lower()]
    
    return render_template('server.html', files=files, extensions=extensions, usernames=usernames)

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@admin_required
@login_required
def delete_file(file_id):
    """
    This route handles file deletion.
    It requires the user to be logged in and have admin privileges.
    It deletes the file from the uploads folder and the database.
    """
    user = Users.query.filter_by(username=session['username']).first()
    if user.user_type == 'admin':
        file_to_delete = Uploads.query.get(file_id)
        if file_to_delete:
            # Get the filename
            filename = file_to_delete.filename
            # Create the file path
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Check if the file exists
            if os.path.exists(file_path):
                # Delete the file
                os.remove(file_path)
                flash(f'File {filename} deleted successfully from the uploads folder.', 'success')
            else:
                flash(f'File {filename} not found in the uploads folder.', 'warning')

            # Delete the record from the database
            m883lfs.session.delete(file_to_delete)
            m883lfs.session.commit()
            flash('File deleted successfully from the database.', 'success')
        else:
            flash('File not found in the database.', 'error')
    else:
        flash('You do not have permission to delete files.', 'error')
    return redirect(url_for('server'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """
    This route handles file uploads.
    It saves the uploaded files to the uploads folder and records them in the database.
    It requires the user to be logged in.
    """
    if 'files[]' not in request.files:
        flash(message="No file part", category="danger")
        return redirect(request.url)

    files = request.files.getlist('files[]')
    uploaded_files = []

    for file in files:
        if file.filename == '':
            flash(message="No selected file", category="danger")
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)  # Secure filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save the file
            file.save(file_path)

            # Get the IP address
            user_info = UserInfo()
            ip_address = user_info.get_ip()

            # Save to database
            new_upload = Uploads(filename=filename, uploaded_by=session['username'], uploaded_ip=ip_address)
            m883lfs.session.add(new_upload)
            m883lfs.session.commit()
            uploaded_files.append(filename)

    if uploaded_files:
        flash(message=f"Files successfully uploaded: {', '.join(uploaded_files)}", category="success")
    else:
        flash(message="No files uploaded", category="info")

    return redirect(url_for('server'))


@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    """
    This route handles file downloads.
    It serves the requested file from the uploads folder.
    It requires the user to be logged in.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/logout", methods=['POST'])
def cikis():
    """
    This route handles user logout.
    It clears the session and redirects to the login page.
    """
    session.clear()
    flash(message="Çıkış Yapıldı",category="info")
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(host=host, port=port, debug=True)