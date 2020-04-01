from flask import render_template, url_for, flash, redirect, request, abort, session
from pkgbuilder import app, db, bcrypt, login_manager
from pkgbuilder.forms import RegistrationForm, LoginForm,AddHostMachineForm,BuildTestPackageForm
from pkgbuilder.models import User,Register_Host,Pkgdetails,Logs
from flask_login import login_user, current_user, logout_user, login_required
import paramiko
import time
import random
import os
import os.path
from os import path
import shutil
import pathlib
from pathlib import Path
import subprocess
import tarfile

#Home Page
@app.route('/',methods=['POST','GET'])
def home():
    pkg_count = len(db.session.query(Pkgdetails).all())
    page = request.args.get('page',1,type=int)
    package = Pkgdetails.query.order_by(Pkgdetails.date_posted.desc()).paginate(page=page,per_page=4)
    return render_template('home.html',title='Home',pkg_count=pkg_count,package=package)


#Login Page
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email or password','danger')
    return render_template('login.html',title='Login',form=form)

#Register Page
@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password,password_decrypted=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Your Account has been created! You are now able to login','success')
        return redirect(url_for('login'))
    return render_template('register.html',title='Register',form=form)

#Register Host Machine
@app.route('/register_host_machine',methods=['POST','GET'])
@login_required
def register_host():
    page = request.args.get('page',1,type=int)
    regs_host_count = db.session.query(Register_Host).count()
    regs_hosts = Register_Host.query.paginate(page=page,per_page=4)
    #Check the status of the Remote Host machines
    remote_ip_status = []
    for i in db.session.query(Register_Host).all():
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            client.connect(str(i),timeout=2)
            stdin, stdout, stderr = client.exec_command("hostname")
            if stdout.channel.recv_exit_status() != 0:
                remote_ip_status = 'Down'
            else:
                remote_ip_status = 'Running'
        except Exception as e:
            print(e)

    return render_template('host_register.html',title='Register Host Machine',regs_hosts=regs_hosts,regs_host_count=regs_host_count,remote_ip_status=remote_ip_status)

#Add Host Machine
@app.route('/addhost',methods=['POST','GET'])
@login_required
def addhost():
    form = AddHostMachineForm()
    
    with open('/root/.ssh/id_rsa.pub',"r") as f:
        publickey_content = f.read()

    if form.validate_on_submit():
        try:
            time.sleep(5)
            remote_host_ip = form.remote_host_ip.data
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            client.connect(remote_host_ip,timeout=10)
            stdin, stdout, stderr = client.exec_command("hostname")
            for line in stdout:
                print(line)
            try:
                rmhost = Register_Host(ipaddress=remote_host_ip,hostname=line,register_remote_host=current_user)
                db.session.add(rmhost)
                db.session.commit()

            except Exception as ee:
                flash(f"Remote Host Machine already Registered !",'info')
                return redirect(url_for('addhost'))

        except Exception as e:
            flash(f"No Valid Connection Found !",'danger')
            return redirect(url_for('addhost'))

        flash(f"Remote Host Machine added successfully",'success')  
        return redirect(url_for('register_host')) 
    return render_template('addhost.html',title='Add Host Machine',form=form,publickey_content=publickey_content)

#Delete Registered Host Machine
@app.route('/delete_reg_hostmachine/<int:host_id>')
@login_required
def delete_host_machine(host_id):
    reg_host = Register_Host.query.get_or_404(host_id)
    db.session.delete(reg_host)
    db.session.commit()
    flash(f"Remote Host Machine Deleted Successfully",'success')
    return redirect(url_for('register_host'))


#Function for building Test Package Workarea
def test_pkg_build_area():
    
    global pkg_build_id, pkg_build_path

    pkg_build_id = random.randint(1111,9999)
    pkg_build_path = '/var/www/html/Test_Packages/'

    #Check if Test Pkg Build area is empty and finish.true is not available
    if not len(os.listdir(pkg_build_path)) == 0:
        #Remove all the Folders which don't have finish.true files
        for f in os.listdir(pkg_build_path):
            file = pathlib.Path(pkg_build_path+f+"/"+"finish.true")
            if not file.exists():
                shutil.rmtree(pkg_build_path+f)

    #Make Test Package working Directory
    os.makedirs(pkg_build_path+str(pkg_build_id))
    
#Building Test Package
@app.route('/build_test_pkg',methods=['POST','GET'])
@login_required
def build_test_pkg():
    form = BuildTestPackageForm()
    test_pkg_build_area()

    if form.validate_on_submit():

        #Check if the Package name has valid prefix
        prefix = form.test_pkg_name.data.split(':',1)
        
        if prefix[0].casefold() not in ['apps','basic','core']:
            flash(f'Missing Prefix in {prefix[0]},while adding packages','danger')
            return redirect(url_for('home'))

        #Create Arch Folder
        os.makedirs(pkg_build_path+str(pkg_build_id)+'/'+str(form.os_arch.data)+'-Bit'+'/'+prefix[0])

        #Check if the remote host is alive
        try:
            remote_host_ip = form.remote_host_ip.data
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            client.connect(str(remote_host_ip),timeout=10)
        except Exception as e:
            flash(f"No Valid Connection Found !",'danger')
            return redirect(url_for('home'))

        #Check if the given absolute path is available in remote machine
        stdin,stdout,stderr = client.exec_command("ls "+form.raw_pkg_path.data)
        if stdout.channel.recv_exit_status() != 0:
            flash(f"Please Check the remote host path",'danger')
            return redirect(url_for('home'))

        #Creating squashfs file    
        stdin,stdout,stderr = client.exec_command("mksquashfs "+form.raw_pkg_path.data+" "+form.raw_pkg_path.data+"/"+prefix[1]+".sq"+" "+"-e "+prefix[1]+".sq")
        #Download the newly created squashfs file
        ftp_client = client.open_sftp()
        ftp_client.get(form.raw_pkg_path.data+"/"+prefix[1]+".sq",pkg_build_path+str(pkg_build_id)+'/'+str(form.os_arch.data)+'-Bit'+'/'+prefix[0]+'/'+prefix[1]+'.sq')
        #MD5SUM Package
        cmd = "md5sum /var/www/html/Test_Packages/"+str(pkg_build_id)+'/'+str(form.os_arch.data)+'-Bit'+'/'+prefix[0]+'/'+prefix[1]+'.sq'
        proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        o,e = proc.communicate()
        md5sum = o.decode('utf8')
        pkg_md5sum = md5sum[:32]
        #Remove sq after download
        stdin,stdout,stderr = client.exec_command("rm -rf  "+form.raw_pkg_path.data+"/"+prefix[1]+'.sq')


        #Check if required patch
        if form.need_patch.data == True :

            #Create Firmware Patch work directory
            os.makedirs(pkg_build_path+str(pkg_build_id)+'/Patch/sda1/data/firmware_update/delete-pkg')
            os.makedirs(pkg_build_path+str(pkg_build_id)+'/Patch/root')

            #Check if remove pkg textfield and install script field is empty
            if len(form.remove.data) == 0 and len(form.install_script.data) == 0:
                flash(f"Patch Fail : Please provide Remove File/Package content or Install Script")
                return redirect(url_for('home'))
            else:
                #First check for remove packages
                remove_pkg_file = form.remove.data
                remove_pkg_file_list = []

                if len(form.remove.data) != 0:
                    #Check for prefix
                    remove_pkg_file_list = remove_pkg_file.split(':')

                    for removeloop in remove_pkg_file_list:
                        prefix = removeloop.split('-',1)

                        if prefix[0].casefold() not in ['core','apps','basic']:
                            flash(f'Missing Prefix in {prefix[0]},while removing package','danger')
                            return redirect(url_for('home'))

                        if prefix[0].casefold() == 'core':
                            Path(pkg_build_path+str(pkg_build_id)+'/Patch/sda1/data/firmware_update/delete-pkg/'+'core:'+prefix[1]).touch()
                        elif prefix[0].casefold() == 'basic':
                            Path(pkg_build_path+str(pkg_build_id)+'/Patch/sda1/data/firmware_update/delete-pkg/'+'basic:'+prefix[1]).touch()
                        else:
                            Path(pkg_build_path+str(pkg_build_id)+'/Patch/sda1/data/firmware_update/delete-pkg/'+'apps:'+prefix[1]).touch()

                if len(form.install_script.data) != 0:
                    #Start writting install script
                    install_script = form.install_script.data
                    install_script_list = []

                    install_script_list = install_script.split(' ')
                    f = open(pkg_build_path+str(pkg_build_id)+'/Patch/root/install',"a+")
                    f.write("#!/bin/bash\n")

                    for i in " ".join(install_script_list):
                        f.write(i)

                    f.close()

                    #Remove ^M from install script
                    subprocess.call(["sed -i -e 's/\r//g' /var/www/html/Test_Packages/"+str(pkg_build_id)+"/Patch/root/install"],shell=True)

                #CHMOD
                subprocess.call(["chmod -R 755 /var/www/html/Test_Packages/"+str(pkg_build_id)],shell=True)

                #Build Final Patch Tar
                pkg_name = form.test_pkg_name.data
                prefix = pkg_name.split(':',-1)
                patchname = prefix[1]+'.tar.bz2'
                tar_file_path = pkg_build_path+str(pkg_build_id)+'/Patch/'+patchname
                tar = tarfile.open(tar_file_path,mode='w:bz2')
                os.chdir(pkg_build_path+str(pkg_build_id)+'/Patch/')
                tar.add(".")
                tar.close()

                #Damage Patch
                cmd = "damage corrupt /var/www/html/Test_Packages/"+str(pkg_build_id)+'/Patch/'+patchname+" 1"
                proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                o,e = proc.communicate()

                #MD5SUM of Patch
                cmd = "md5sum /var/www/html/Test_Packages/"+str(pkg_build_id)+"/Patch/"+patchname
                proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                o,e = proc.communicate()
                md5sum = o.decode('utf8')
                patch_md5sum = md5sum[:32]
                #Update the Database
                pkg_update = Pkgdetails(pkgbuild_id=str(pkg_build_id),author=current_user,pkgname=prefix[1],description=form.test_pkg_description.data,md5sum_pkg=pkg_md5sum,md5sum_patch=patch_md5sum,os_arch=form.os_arch.data)
                db.session.add(pkg_update)
                db.session.commit()
        
                #Finish
                Path(pkg_build_path+str(pkg_build_id)+"/"+"finish.true").touch()
                
                return redirect(url_for('home'))
        else:

            patch_md5sum = 'None'
        
            #Update the Database
            pkg_update = Pkgdetails(pkgbuild_id=str(pkg_build_id),author=current_user,pkgname=prefix[1],description=form.test_pkg_description.data,md5sum_pkg=pkg_md5sum,md5sum_patch=patch_md5sum,os_arch=form.os_arch.data)
            db.session.add(pkg_update)
            db.session.commit()
            
            #Finish
            Path(pkg_build_path+str(pkg_build_id)+"/"+"finish.true").touch()

            return redirect(url_for('home'))
    return render_template('build_test_pkg.html',title='Build Test Package',form=form,pkg_build_id=pkg_build_id)


#Delete the Package permanantly
@app.route('/delete_pkg/<int:pkg_id>',methods=['POST','GET'])
@login_required
def delete_pkg(pkg_id):

    pkg_info = Pkgdetails.query.get_or_404(pkg_id)
    log_info = Logs(pkgbuild_id=pkg_info.pkgbuild_id,pkgname=pkg_info.pkgname,md5sum_pkg=pkg_info.md5sum_pkg,md5sum_patch=pkg_info.md5sum_patch,logmeup=current_user)
    db.session.add(log_info)
    db.session.commit()

    if pkg_info.author != current_user:
        abort(403)

    db.session.delete(pkg_info)
    db.session.commit()
    pkg_build_path = '/var/www/html/Test_Packages/'
    pkgbuild = pkg_info.pkgbuild_id
    
    shutil.rmtree(pkg_build_path+str(pkgbuild))

    flash('Package has been deleted!','success')
    return redirect(url_for('home'))

#Move to Final Package
@app.route('/move_final_pkg/<int:pkg_id>',methods=['POST','GET'])
def move_final_pkg(pkg_id):
    pkg_info = Pkgdetails.query.get_or_404(pkg_id)
    pkgbuild = pkg_info.pkgbuild_id
    pkg_build_path = '/var/www/html/Test_Packages/'
    os.makedirs(pkg_build_path+str(pkgbuild)+'/Final')

    if pkg_info.author != current_user:
        abort(403)

    for root, dirs, files in os.walk(pkg_build_path+str(pkgbuild)):
        for file in files:
            if file.endswith(".sq"):
                sq_path = os.path.join(root, file)
                cmd = "mv "+sq_path+" "+pkg_build_path+str(pkgbuild)+'/Final/'
                proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                o,e = proc.communicate()

    flash('Package moved to Final Stage!','success')          
    return redirect(url_for('home'))

#Logs
@app.route('/logs',methods=['POST','GET'])
@login_required
def logs():
    
    page = request.args.get('page',1,type=int)
    log_count = db.session.query(Logs).count()
    logs_info = Logs.query.order_by(Logs.date_removed.desc()).paginate(page=page,per_page=4)

    return render_template('log.html',title='Logs',logs_info=logs_info,log_count=log_count)

#Logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))