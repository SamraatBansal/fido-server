CREATE TABLE mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    external_type VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(credential_id, external_id, external_type)
);

CREATE INDEX idx_mappings_credential_id ON mappings(credential_id);
CREATE INDEX idx_mappings_external_id ON mappings(external_id);
CREATE INDEX idx_mappings_external_type ON mappings(external_type);