```sql
-- Tables required by Spring Authorization Server (simplified). You can find the canonical DDL in the project docs.
-- Registered clients
CREATE TABLE IF NOT EXISTS oauth2_registered_client (
id VARCHAR(100) PRIMARY KEY,
client_id VARCHAR(100) NOT NULL,
client_id_issued_at TIMESTAMP,
client_secret VARCHAR(200),
client_secret_expires_at TIMESTAMP,
client_name VARCHAR(200),
client_authentication_methods TEXT,
authorization_grant_types TEXT,
redirect_uris TEXT,
scopes TEXT,
client_settings TEXT,
token_settings TEXT
);
Authorization (tokens)
CREATE TABLE IF NOT EXISTS oauth2_authorization (
                                                    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100),
    principal_name VARCHAR(200),
    authorization_grant_type VARCHAR(100),
    attributes TEXT,
    state VARCHAR(500),
    authorization_code_value TEXT,
    authorization_code_issued_at TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    access_token_value TEXT,
    access_token_issued_at TIMESTAMP,
    access_token_expires_at TIMESTAMP,
    access_token_metadata TEXT,
    refresh_token_value TEXT,
    refresh_token_issued_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    refresh_token_metadata TEXT
    );
-- Authorization consent (optional)
CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
                                                            id SERIAL PRIMARY KEY,
                                                            registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorities TEXT
    );
```