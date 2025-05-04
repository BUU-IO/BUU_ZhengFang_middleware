
CREATE TABLE clients (
	id UUID NOT NULL, 
	client_id VARCHAR(64) NOT NULL, 
	client_secret VARCHAR(256) NOT NULL, 
	redirect_uris VARCHAR(1024) NOT NULL, 
	is_confidential BOOLEAN, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (client_id)
);




CREATE TABLE users (
	id UUID NOT NULL, 
	username VARCHAR(64) NOT NULL, 
	password_hash VARCHAR(256) NOT NULL, 
	identify VARCHAR(64), 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (username)
);




CREATE TABLE authorization_codes (
	code VARCHAR(128) NOT NULL, 
	client_id UUID NOT NULL, 
	redirect_uri VARCHAR(512) NOT NULL, 
	user_account VARCHAR(256) NOT NULL, 
	expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	used BOOLEAN, 
	scope VARCHAR(256), 
	PRIMARY KEY (code), 
	FOREIGN KEY(client_id) REFERENCES clients (id)
);

