START TRANSACTION;

use userdetails;

create table signedupusers(
id int primary key not null auto_increment,
email varchar(256) UNIQUE NOT NULL,
pass char(60) NOT NULL 
);

COMMIT;