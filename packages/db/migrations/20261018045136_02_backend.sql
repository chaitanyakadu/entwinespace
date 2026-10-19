-- ============================================================
-- APPLICATION
-- ============================================================

-- Profile
CREATE TABLE profile
(
    user_id UUID PRIMARY KEY,
    status TEXT,
    avatar TEXT,
    banner TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_profile_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- Settings
CREATE TABLE settings
(
    user_id UUID PRIMARY KEY,

    notifications INTEGER,
    nearby_audio BOOLEAN,
    keybindings TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_settings_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- Payment
CREATE TABLE payment
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,

    razorpay_payment_id TEXT,
    entity TEXT,
    amount NUMERIC,
    currency TEXT,
    status TEXT,
    refund_status TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_payment_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- Subscription
CREATE TABLE subscription
(
    user_id UUID PRIMARY KEY,

    premium_since TIMESTAMPTZ,
    premium_type INTEGER,
    payment_id UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_subscription_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_subscription_payment
        FOREIGN KEY (payment_id)
        REFERENCES payment(id)
        ON DELETE SET NULL
);


-- ============================================================
-- SPACE
-- ============================================================

CREATE TABLE space
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    admin_id UUID NOT NULL,

    name TEXT NOT NULL,
    bio TEXT,
    avatar TEXT,
    banner TEXT,

    deactivated BOOLEAN NOT NULL DEFAULT FALSE,
    public BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_space_admin
        FOREIGN KEY (admin_id)
        REFERENCES users(id)
        ON DELETE RESTRICT
);


CREATE TYPE space_member_role AS ENUM
(
    'admin',
    'moderator',
    'member'
);


CREATE TABLE space_member
(
    space_id UUID NOT NULL,
    user_id UUID NOT NULL,

    role space_member_role NOT NULL DEFAULT 'member',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (space_id, user_id),

    CONSTRAINT fk_space_member_space
        FOREIGN KEY (space_id)
        REFERENCES space(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_space_member_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_space_member_user_id
    ON space_member(user_id);


-- ============================================================
-- SERVER
-- ============================================================

CREATE TABLE server
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id UUID NOT NULL,

    name TEXT NOT NULL,
    bio TEXT,
    avatar TEXT,

    read_only BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_server_space
        FOREIGN KEY (space_id)
        REFERENCES space(id)
        ON DELETE CASCADE
);


CREATE TABLE server_member
(
    server_id UUID NOT NULL,
    user_id UUID NOT NULL,

    role space_member_role NOT NULL DEFAULT 'member',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (server_id, user_id),

    CONSTRAINT fk_server_member_server
        FOREIGN KEY (server_id)
        REFERENCES server(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_server_member_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_server_member_user_id
    ON server_member(user_id);


-- ============================================================
-- CHANNEL
-- ============================================================

CREATE TABLE channel
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL,

    name TEXT NOT NULL,
    bio TEXT,
    avatar TEXT,

    public BOOLEAN NOT NULL DEFAULT FALSE,
    read_only BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_channel_server
        FOREIGN KEY (server_id)
        REFERENCES server(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_channel_server_id
    ON channel(server_id);


-- ============================================================
-- MESSAGE
-- ============================================================

CREATE TABLE message
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL,
    author_id UUID NOT NULL,

    content TEXT NOT NULL,

    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_message_channel
        FOREIGN KEY (channel_id)
        REFERENCES channel(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_message_author
        FOREIGN KEY (author_id)
        REFERENCES users(id)
        ON DELETE RESTRICT
);


CREATE INDEX idx_message_channel_id
    ON message(channel_id);

CREATE INDEX idx_message_author_id
    ON message(author_id);


-- ============================================================
-- PINNED MESSAGE
-- ============================================================

CREATE TABLE pinned_msg
(
    channel_id UUID NOT NULL,
    msg_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (channel_id, msg_id),

    CONSTRAINT fk_pinned_message_channel
        FOREIGN KEY (channel_id)
        REFERENCES channel(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_pinned_message_message
        FOREIGN KEY (msg_id)
        REFERENCES message(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_pinned_msg_msg_id
    ON pinned_msg(msg_id);


-- ============================================================
-- ATTACHMENTS
-- ============================================================

CREATE TABLE attachments
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    msg_id UUID NOT NULL,

    url TEXT NOT NULL,
    content_type TEXT,
    filename TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_attachment_message
        FOREIGN KEY (msg_id)
        REFERENCES message(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_attachments_msg_id
    ON attachments(msg_id);


-- ============================================================
-- REACTIONS
-- ============================================================

CREATE TABLE reactions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    msg_id UUID NOT NULL,
    user_id UUID NOT NULL,

    emoji TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_reaction_message
        FOREIGN KEY (msg_id)
        REFERENCES message(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_reaction_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_reaction_message_user_emoji
        UNIQUE (msg_id, user_id, emoji)
);


CREATE INDEX idx_reactions_msg_id
    ON reactions(msg_id);

CREATE INDEX idx_reactions_user_id
    ON reactions(user_id);
