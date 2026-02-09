# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Unit tests for Authentication and Authorization (JWT + RBAC).
Tests token creation, validation, permission checks, and audit logging.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import jwt
from passlib.context import CryptContext


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password(self):
        """Test password hashing."""
        from services.shared.auth import hash_password

        password = "SecurePassword123!"
        hashed = hash_password(password)

        assert hashed != password
        assert len(hashed) > 50
        assert hashed.startswith("$2b$12$") or hashed.startswith("$2b$")

    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        from services.shared.auth import hash_password, verify_password

        password = "SecurePassword123!"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        from services.shared.auth import hash_password, verify_password

        password = "SecurePassword123!"
        wrong_password = "WrongPassword456!"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) is False

    def test_hash_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        from services.shared.auth import hash_password

        password1 = "Password1!"
        password2 = "Password2!"

        hash1 = hash_password(password1)
        hash2 = hash_password(password2)

        assert hash1 != hash2

    def test_hash_same_password_different_hashes(self):
        """Test that same password produces different hashes (salt)."""
        from services.shared.auth import hash_password

        password = "SamePassword!"

        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2  # Different salts
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestTokenCreation:
    """Test JWT token creation."""

    def test_create_access_token(self):
        """Test access token creation."""
        from services.shared.auth import create_access_token
        from services.shared.auth import User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        token = create_access_token(user)

        assert isinstance(token, str)
        assert len(token) > 50

        # Decode and verify
        decoded = jwt.decode(
            token,
            "test_secret_key_change_in_production",
            algorithms=["HS256"]
        )

        assert decoded["sub"] == "user123"
        assert decoded["username"] == "testuser"
        assert decoded["role"] == "analyst"

    def test_create_refresh_token(self):
        """Test refresh token creation."""
        from services.shared.auth import create_refresh_token
        from services.shared.auth import User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        token = create_refresh_token(user)

        assert isinstance(token, str)

        decoded = jwt.decode(
            token,
            "test_secret_key_change_in_production",
            algorithms=["HS256"]
        )

        assert decoded["sub"] == "user123"
        assert "exp" in decoded
        # Refresh token should have longer expiration
        exp = datetime.fromtimestamp(decoded["exp"])
        assert exp > datetime.now() + timedelta(days=6)

    def test_token_includes_jti(self):
        """Test token includes JWT ID for revocation tracking."""
        from services.shared.auth import create_access_token
        from services.shared.auth import User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        token = create_access_token(user)

        decoded = jwt.decode(
            token,
            "test_secret_key_change_in_production",
            algorithms=["HS256"]
        )

        assert "jti" in decoded
        assert len(decoded["jti"]) > 0


class TokenValidation:
    """Test JWT token validation."""

    def test_validate_access_token_success(self):
        """Test successful access token validation."""
        from services.shared.auth import create_access_token, validate_token
        from services.shared.auth import User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        token = create_access_token(user)
        decoded = validate_token(token)

        assert decoded is not None
        assert decoded["sub"] == "user123"
        assert decoded["username"] == "testuser"

    def test_validate_token_invalid(self):
        """Test invalid token validation."""
        from services.shared.auth import validate_token

        invalid_token = "invalid.token.here"

        decoded = validate_token(invalid_token)

        assert decoded is None

    def test_validate_token_expired(self):
        """Test expired token validation."""
        from services.shared.auth import create_access_token
        from services.shared.auth import User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        # Create token with very short expiration
        import time
        with patch('services.shared.auth.AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES', -1):
            token = create_access_token(user)

        decoded = validate_token(token)

        assert decoded is None

    def test_validate_token_wrong_secret(self):
        """Test token validation with wrong secret."""
        import jwt

        token = jwt.encode(
            {"sub": "user123", "exp": datetime.now() + timedelta(minutes=30)},
            "wrong_secret",
            algorithm="HS256"
        )

        from services.shared.auth import validate_token
        decoded = validate_token(token)

        assert decoded is None


class TestRBACPermissions:
    """Test Role-Based Access Control permissions."""

    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions."""
        from services.shared.auth import has_permission, UserRole, Permission, User

        admin_user = User(
            user_id="admin1",
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            permissions=[]
        )

        for permission in Permission:
            assert has_permission(admin_user, permission) is True

    def test_analyst_permissions(self):
        """Test analyst role has correct permissions."""
        from services.shared.auth import has_permission, UserRole, Permission, User

        analyst = User(
            user_id="analyst1",
            username="analyst",
            email="analyst@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        # Analyst should have these permissions
        assert has_permission(analyst, Permission.ALERT_READ) is True
        assert has_permission(analyst, Permission.ALERT_UPDATE) is True
        assert has_permission(analyst, Permission.TRIAGE_CREATE) is True

        # But not these
        assert has_permission(analyst, Permission.USER_MANAGE) is False
        assert has_permission(analyst, Permission.SYSTEM_CONFIG) is False

    def test_operator_permissions(self):
        """Test operator role has correct permissions."""
        from services.shared.auth import has_permission, UserRole, Permission, User

        operator = User(
            user_id="operator1",
            username="operator",
            email="operator@example.com",
            role=UserRole.OPERATOR,
            permissions=[]
        )

        assert has_permission(operator, Permission.ALERT_READ) is True
        assert has_permission(operator, Permission.ALERT_CREATE) is True
        assert has_permission(operator, Permission.WORKFLOW_EXECUTE) is True

        assert has_permission(operator, Permission.TRIAGE_DELETE) is False
        assert has_permission(operator, Permission.USER_MANAGE) is False

    def test_viewer_permissions(self):
        """Test viewer role has read-only permissions."""
        from services.shared.auth import has_permission, UserRole, Permission, User

        viewer = User(
            user_id="viewer1",
            username="viewer",
            email="viewer@example.com",
            role=UserRole.VIEWER,
            permissions=[]
        )

        assert has_permission(viewer, Permission.ALERT_READ) is True
        assert has_permission(viewer, Permission.DASHBOARD_VIEW) is True

        assert has_permission(viewer, Permission.ALERT_CREATE) is False
        assert has_permission(viewer, Permission.ALERT_UPDATE) is False
        assert has_permission(viewer, Permission.ALERT_DELETE) is False

    def test_auditor_permissions(self):
        """Test auditor role has audit log access."""
        from services.shared.auth import has_permission, UserRole, Permission, User

        auditor = User(
            user_id="auditor1",
            username="auditor",
            email="auditor@example.com",
            role=UserRole.AUDITOR,
            permissions=[]
        )

        assert has_permission(auditor, Permission.AUDIT_LOG_READ) is True
        assert has_permission(auditor, Permission.REPORT_VIEW) is True

        assert has_permission(auditor, Permission.ALERT_CREATE) is False
        assert has_permission(auditor, Permission.SYSTEM_CONFIG) is False

    def test_custom_permissions(self):
        """Test user with custom permissions."""
        from services.shared.auth import has_permission, Permission, User

        user = User(
            user_id="custom1",
            username="custom",
            email="custom@example.com",
            role=None,  # No role
            permissions=[Permission.ALERT_READ, Permission.TRIAGE_CREATE]
        )

        assert has_permission(user, Permission.ALERT_READ) is True
        assert has_permission(user, Permission.TRIAGE_CREATE) is True
        assert has_permission(user, Permission.ALERT_DELETE) is False


class TestRoleRequirements:
    """Test role-based access checks."""

    def test_require_role_admin(self):
        """Test require role decorator for admin."""
        from services.shared.auth import require_role, UserRole, User
        from fastapi import HTTPException

        admin_user = User(
            user_id="admin1",
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            permissions=[]
        )

        # Should not raise
        require_role(admin_user, UserRole.ADMIN)

        # Should raise for non-admin
        analyst_user = User(
            user_id="analyst1",
            username="analyst",
            email="analyst@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        with pytest.raises(HTTPException) as exc_info:
            require_role(analyst_user, UserRole.ADMIN)

        assert exc_info.value.status_code == 403

    def test_require_role_any_of(self):
        """Test require role with multiple allowed roles."""
        from services.shared.auth import require_role_any_of, UserRole, User

        analyst_user = User(
            user_id="analyst1",
            username="analyst",
            email="analyst@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        # Should pass if user has one of the required roles
        require_role_any_of(analyst_user, [UserRole.ADMIN, UserRole.ANALYST])

        viewer_user = User(
            user_id="viewer1",
            username="viewer",
            email="viewer@example.com",
            role=UserRole.VIEWER,
            permissions=[]
        )

        with pytest.raises(HTTPException):
            require_role_any_of(viewer_user, [UserRole.ADMIN, UserRole.ANALYST])


class TestAuditLogging:
    """Test audit logging for security events."""

    @pytest.mark.asyncio
    async def test_log_audit_event(self):
        """Test logging audit event."""
        from services.shared.auth import log_audit_event, AuditAction, User

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=None,
            permissions=[]
        )

        with patch('services.shared.auth.audit_logger') as mock_logger:
            await log_audit_event(
                user=user,
                action=AuditAction.USER_LOGIN,
                resource="auth",
                details={"ip": "192.168.1.1"}
            )

            mock_logger.info.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_audit_event_all_actions(self):
        """Test logging all audit actions."""
        from services.shared.auth import log_audit_event, AuditAction, User

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=None,
            permissions=[]
        )

        with patch('services.shared.auth.audit_logger'):
            for action in AuditAction:
                await log_audit_event(
                    user=user,
                    action=action,
                    resource="test",
                    details={}
                )

    @pytest.mark.asyncio
    async def test_audit_log_includes_required_fields(self):
        """Test audit log includes all required fields."""
        from services.shared.auth import log_audit_event, AuditAction, User
        from datetime import datetime

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=None,
            permissions=[]
        )

        with patch('services.shared.auth.audit_logger') as mock_logger:
            await log_audit_event(
                user=user,
                action=AuditAction.ALERT_CREATED,
                resource="alert",
                details={"alert_id": "123"}
            )

            call_args = mock_logger.info.call_args
            log_data = call_args[1]

            assert "user_id" in log_data["extra"]
            assert "action" in log_data["extra"]
            assert "resource" in log_data["extra"]
            assert "timestamp" in log_data["extra"]


class TestDataEncryption:
    """Test sensitive data encryption."""

    def test_encrypt_decrypt_data(self):
        """Test encrypting and decrypting data."""
        from services.shared.auth import encrypt_data, decrypt_data

        original_data = "sensitive_api_key_12345"

        encrypted = encrypt_data(original_data)
        decrypted = decrypt_data(encrypted)

        assert decrypted == original_data
        assert encrypted != original_data

    def test_encrypt_different_results(self):
        """Test encryption produces different results (random IV)."""
        from services.shared.auth import encrypt_data

        data = "same_data"

        encrypted1 = encrypt_data(data)
        encrypted2 = encrypt_data(data)

        # Due to random IV, encrypted results should differ
        assert encrypted1 != encrypted2

        # But both should decrypt to same value
        from services.shared.auth import decrypt_data
        assert decrypt_data(encrypted1) == data
        assert decrypt_data(encrypted2) == data

    def test_decrypt_invalid_data(self):
        """Test decrypting invalid data."""
        from services.shared.auth import decrypt_data

        with pytest.raises(Exception):
            decrypt_data("invalid_encrypted_data")


class TestFastAPIDependencies:
    """Test FastAPI dependency functions."""

    @pytest.mark.asyncio
    async def test_get_current_user_valid_token(self):
        """Test get_current_user with valid token."""
        from services.shared.auth import create_access_token, get_current_user, User, UserRole
        from fastapi import Request

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        token = create_access_token(user)

        mock_request = Mock(spec=Request)
        mock_request.headers = {"Authorization": f"Bearer {token}"}

        with patch('services.shared.auth.validate_token', return_value={
            "sub": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "role": "analyst"
        }):
            retrieved_user = await get_current_user(mock_request)

            assert retrieved_user is not None
            assert retrieved_user.user_id == "user123"

    @pytest.mark.asyncio
    async def test_get_current_user_no_token(self):
        """Test get_current_user with no token."""
        from services.shared.auth import get_current_user
        from fastapi import Request, HTTPException

        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(mock_request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_require_permission_decorator(self):
        """Test require_permission decorator."""
        from services.shared.auth import require_permission, Permission, User, UserRole
        from fastapi import HTTPException

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        # Should pass for allowed permission
        await require_permission(Permission.ALERT_READ)(lambda: None)(user)

        # Should fail for denied permission
        with pytest.raises(HTTPException) as exc_info:
            await require_permission(Permission.USER_MANAGE)(lambda: None)(user)

        assert exc_info.value.status_code == 403


class TestTokenRotation:
    """Test token rotation and refresh logic."""

    def test_refresh_token_rotation(self):
        """Test refresh token rotation."""
        from services.shared.auth import rotate_refresh_token
        from services.shared.auth import create_refresh_token, User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        old_token = create_refresh_token(user)
        new_token = rotate_refresh_token(old_token, user)

        assert new_token != old_token
        assert isinstance(new_token, str)

        # Old token should be invalidated (blacklisted)
        from services.shared.auth import is_token_blacklisted
        assert is_token_blacklisted(old_token) is True

    def test_token_blacklist(self):
        """Test token blacklisting."""
        from services.shared.auth import blacklist_token, is_token_blacklisted

        token = "test_token_12345"

        assert is_token_blacklisted(token) is False

        blacklist_token(token)

        assert is_token_blacklisted(token) is True


class TestSessionManagement:
    """Test session management and timeout."""

    def test_session_creation(self):
        """Test creating a user session."""
        from services.shared.auth import create_session, User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        session = create_session(user)

        assert "session_id" in session
        assert "user_id" in session
        assert "created_at" in session
        assert "expires_at" in session

    def test_session_validation(self):
        """Test session validation."""
        from services.shared.auth import create_session, validate_session, User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        session = create_session(user)

        # Should be valid
        assert validate_session(session["session_id"]) is True

    def test_session_expiration(self):
        """Test session expiration."""
        from services.shared.auth import create_session, validate_session, User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        # Create session with very short expiration
        with patch('services.shared.auth.AuthConfig.SESSION_TIMEOUT_MINUTES', -1):
            session = create_session(user)

        # Should be expired
        assert validate_session(session["session_id"]) is False

    def test_concurrent_session_limit(self):
        """Test concurrent session limit."""
        from services.shared.auth import create_session, get_active_sessions, User, UserRole

        user = User(
            user_id="user123",
            username="testuser",
            email="test@example.com",
            role=UserRole.ANALYST,
            permissions=[]
        )

        # Create 3 sessions
        sessions = [create_session(user) for _ in range(3)]

        active_sessions = get_active_sessions(user.user_id)

        # Should limit to 3 concurrent sessions
        assert len(active_sessions) <= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
