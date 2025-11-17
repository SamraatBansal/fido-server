CREATE TABLE registration_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge BYTEA NOT NULL,
    state_data BYTEA NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE authentication_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge BYTEA NOT NULL,
    state_data BYTEA NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_registration_challenges_user_id ON registration_challenges(user_id);
CREATE INDEX idx_registration_challenges_expires_at ON registration_challenges(expires_at);
CREATE INDEX idx_authentication_challenges_user_id ON authentication_challenges(user_id);
CREATE INDEX idx_authentication_challenges_expires_at ON authentication_challenges(expires_at);