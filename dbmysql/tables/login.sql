START TRANSACTION;

create table loggedinusers(
email varchar(256) PRIMARY KEY UNIQUE NOT NULL,
cookie char(60) NOT NULL 
);

COMMIT;