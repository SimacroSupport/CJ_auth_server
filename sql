use mysql;
CREATE DATABASE CJ_Websim_Member;
CREATE DATABASE CJ_Websim_Auth;
CREATE DATABASE CJ_Websim_Log;
CREATE DATABASE CJ_Websim_Dormant;
CREATE DATABASE CJ_Websim_Withdrawal;

CREATE USER 'cjwebsim'@'localhost' IDENTIFIED BY 'iG!8A4#YnP';
GRANT ALL PRIVILEGES ON CJ_Websim_Member.* TO 'cjwebsim'@'localhost';
GRANT ALL PRIVILEGES ON CJ_Websim_Auth.* TO 'cjwebsim'@'localhost';
GRANT ALL PRIVILEGES ON CJ_Websim_Log.* TO 'cjwebsim'@'localhost';
GRANT ALL PRIVILEGES ON CJ_Websim_Dormant.* TO 'cjwebsim'@'localhost';
GRANT ALL PRIVILEGES ON CJ_Websim_Withdrawal.* TO 'cjwebsim'@'localhost';

use CJ_Websim_Member;
CREATE TABLE Users (
    user_no INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(40)
    -- login_type VARCHAR(20) -- "SSO" / "EXCEPT"
);
CREATE TABLE Profile (
    profile_id INT AUTO_INCREMENT PRIMARY KEY,
    user_no INT,
    cell_phone VARCHAR(128), -- base64 encryt
    email VARCHAR(128), -- base64 encryt
    -- cj_world_account VARCHAR(30), -- base64 encryt
    join_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    authentication_level VARCHAR(20) NOT NULL, -- 'User'/'Admin'
    user_name VARCHAR(40),
    FOREIGN KEY(user_no) REFERENCES CJ_Websim_Member.Users(user_no) ON DELETE CASCADE
);

use CJ_Websim_Auth;
CREATE TABLE Password (
    password_id INT AUTO_INCREMENT PRIMARY KEY,
    user_no INT,
    salt VARCHAR(256),
    update_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, 
    password VARCHAR(256),
    FOREIGN KEY(user_no) REFERENCES CJ_Websim_Member.Users(user_no) ON DELETE CASCADE
);


use CJ_Websim_Log;
CREATE TABLE User_activity_log (
    user_activity_log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_no INT,
    user_name VARCHAR(40),
    action_type VARCHAR(40), -- CALULATION / LOGIN / MENU
    meta_data VARCHAR(256), -- calculation log / status code / menu name
    log_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Withdrawal_log (
    withdrawal_log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_no INT,
    user_name VARCHAR(40),
    withdrawl_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE Login_log (
    login_log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_no INT,
    user_name VARCHAR(40),
    status_code TINYINT, -- 0: Fail, 1: Success
    login_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

USE CJ_Websim_Member;
ALTER TABLE Profile CONVERT TO CHARSET UTF8;
ALTER TABLE Users CONVERT TO CHARSET UTF8;
USE CJ_Websim_Log;
ALTER TABLE User_activity_log CONVERT TO CHARSET UTF8;
ALTER TABLE Login_log CONVERT TO CHARSET UTF8;
ALTER TABLE Withdrawal_log CONVERT TO CHARSET UTF8;

