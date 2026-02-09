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
Unit tests for User Management Service.
Tests user CRUD operations, authentication, and session management.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta


class TestUserCreation:
    """Test user creation and registration."""

    @pytest.mark.asyncio
    async def test_create_user_success(self):
        """Test successful user creation."""
        from services.user_management.main import create_user
        from services.shared.auth import UserRole

        user_data = {
            "username": "john.doe",
            "email": "john.doe@example.com",
            "password": "SecurePass123!",
            "role": UserRole.ANALYST,
            "full_name": "John Doe",
            "department": "Security"
        }

        with patch('services.user_management.main.hash_password') as mock_hash, \
             patch('services.user_management.main.db_manager') as mock_db:

            mock_hash.return_value = "hashed_password"
            mock_db.fetch_one.return_value = None  # No existing user

            result = await create_user(user_data)

            assert result["success"] is True
            assert result["user"]["username"] == "john.doe"
            assert "user_id" in result["user"]

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self):
        """Test creating user with duplicate username fails."""
        from services.user_management.main import create_user

        user_data = {
            "username": "john.doe",
            "email": "john.doe@example.com",
            "password": "SecurePass123!"
        }

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {"username": "john.doe"}

            result = await create_user(user_data)

            assert result["success"] is False
            assert "duplicate" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_create_user_weak_password(self):
        """Test weak password is rejected."""
        from services.user_management.main import create_user

        user_data = {
            "username": "john.doe",
            "email": "john.doe@example.com",
            "password": "weak"  # Too short
        }

        result = await create_user(user_data)

        assert result["success"] is False
        assert "password" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self):
        """Test invalid email is rejected."""
        from services.user_management.main import create_user

        user_data = {
            "username": "john.doe",
            "email": "invalid-email",
            "password": "SecurePass123!"
        }

        result = await create_user(user_data)

        assert result["success"] is False
        assert "email" in result.get("error", "").lower()


class TestUserAuthentication:
    """Test user authentication logic."""

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self):
        """Test successful user authentication."""
        from services.user_management.main import authenticate_user
        from services.shared.auth import hash_password

        password = "SecurePass123!"
        hashed = hash_password(password)

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "password_hash": hashed,
                "role": "analyst",
                "active": True
            }

            result = await authenticate_user("john.doe", password)

            assert result["success"] is True
            assert result["user"]["username"] == "john.doe"

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self):
        """Test authentication fails with wrong password."""
        from services.user_management.main import authenticate_user
        from services.shared.auth import hash_password

        password = "SecurePass123!"
        hashed = hash_password(password)

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "username": "john.doe",
                "password_hash": hashed,
                "active": True
            }

            result = await authenticate_user("john.doe", "WrongPassword!")

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self):
        """Test authentication fails for non-existent user."""
        from services.user_management.main import authenticate_user

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = None

            result = await authenticate_user("nonexistent", "password")

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self):
        """Test authentication fails for inactive user."""
        from services.user_management.main import authenticate_user
        from services.shared.auth import hash_password

        password = "SecurePass123!"
        hashed = hash_password(password)

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "username": "john.doe",
                "password_hash": hashed,
                "active": False  # Inactive
            }

            result = await authenticate_user("john.doe", password)

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_authenticate_with_rate_limit(self):
        """Test authentication rate limiting."""
        from services.user_management.main import authenticate_user

        with patch('services.user_management.main.db_manager') as mock_db, \
             patch('services.user_management.main.check_login_rate_limit') as mock_rate:

            mock_rate.return_value = False  # Rate limit exceeded

            result = await authenticate_user("john.doe", "password")

            assert result["success"] is False
            assert "rate" in result.get("error", "").lower()


class TestUserRetrieval:
    """Test user retrieval operations."""

    @pytest.mark.asyncio
    async def test_get_user_by_id(self):
        """Test getting user by ID."""
        from services.user_management.main import get_user

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "role": "analyst"
            }

            user = await get_user("usr-001")

            assert user["user_id"] == "usr-001"

    @pytest.mark.asyncio
    async def test_get_user_by_username(self):
        """Test getting user by username."""
        from services.user_management.main import get_user_by_username

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "username": "john.doe"
            }

            user = await get_user_by_username("john.doe")

            assert user["username"] == "john.doe"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self):
        """Test getting non-existent user returns None."""
        from services.user_management.main import get_user

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = None

            user = await get_user("nonexistent")

            assert user is None

    @pytest.mark.asyncio
    async def test_list_users(self):
        """Test listing users with pagination."""
        from services.user_management.main import list_users

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_all.return_value = [
                {"user_id": "usr-001", "username": "john.doe"},
                {"user_id": "usr-002", "username": "jane.smith"}
            ]

            users = await list_users(page=1, limit=10)

            assert len(users) == 2


class TestUserUpdate:
    """Test user update operations."""

    @pytest.mark.asyncio
    async def test_update_user_profile(self):
        """Test updating user profile."""
        from services.user_management.main import update_user

        user_id = "usr-001"
        updates = {
            "full_name": "John Updated Doe",
            "department": "Security Operations"
        }

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {"user_id": user_id}

            result = await update_user(user_id, updates)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_update_user_role(self):
        """Test updating user role."""
        from services.user_management.main import update_user_role
        from services.shared.auth import UserRole

        with patch('services.user_management.main.db_manager') as mock_db, \
             patch('services.user_management.main.log_role_change') as mock_log:

            mock_db.fetch_one.return_value = {"user_id": "usr-001"}

            result = await update_user_role("usr-001", UserRole.ADMIN)

            assert result["success"] is True
            mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_password(self):
        """Test updating user password."""
        from services.user_management.main import update_user_password

        with patch('services.user_management.main.db_manager') as mock_db, \
             patch('services.user_management.main.hash_password') as mock_hash, \
             patch('services.user_management.main.invalidate_user_sessions') as mock_invalidate:

            mock_db.fetch_one.return_value = {"user_id": "usr-001"}
            mock_hash.return_value = "new_hashed"

            result = await update_user_password(
                "usr-001",
                "OldPass123!",
                "NewPass456!"
            )

            assert result["success"] is True
            mock_invalidate.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_wrong_current_password(self):
        """Test password update fails with wrong current password."""
        from services.user_management.main import update_user_password
        from services.shared.auth import hash_password, verify_password

        current_pass = "OldPass123!"
        hashed = hash_password(current_pass)

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "password_hash": hashed
            }

            result = await update_user_password(
                "usr-001",
                "WrongOldPass!",
                "NewPass456!"
            )

            assert result["success"] is False


class TestUserDeactivation:
    """Test user deactivation and deletion."""

    @pytest.mark.asyncio
    async def test_deactivate_user(self):
        """Test deactivating a user."""
        from services.user_management.main import deactivate_user

        with patch('services.user_management.main.db_manager') as mock_db, \
             patch('services.user_management.main.invalidate_user_sessions') as mock_invalidate:

            mock_db.fetch_one.return_value = {"user_id": "usr-001", "active": True}

            result = await deactivate_user("usr-001")

            assert result["success"] is True
            mock_invalidate.assert_called_once()

    @pytest.mark.asyncio
    async def test_activate_user(self):
        """Test activating a user."""
        from services.user_management.main import activate_user

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {"user_id": "usr-001", "active": False}

            result = await activate_user("usr-001")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_user_soft(self):
        """Test soft deleting a user."""
        from services.user_management.main import delete_user

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {"user_id": "usr-001", "deleted": False}

            result = await delete_user("usr-001", soft_delete=True)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_user_hard(self):
        """Test hard deleting a user."""
        from services.user_management.main import delete_user

        with patch('services.user_management.main.db_manager') as mock_db, \
             patch('services.user_management.main.invalidate_user_sessions') as mock_invalidate:

            mock_db.fetch_one.return_value = {"user_id": "usr-001"}

            result = await delete_user("usr-001", soft_delete=False)

            assert result["success"] is True


class TestPasswordManagement:
    """Test password management operations."""

    @pytest.mark.asyncio
    async def test_request_password_reset(self):
        """Test requesting password reset."""
        from services.user_management.main import request_password_reset

        with patch('services.user_management.main.db_manager') as mock_db, \
             patch('services.user_management.main.send_password_reset_email') as mock_email:

            mock_db.fetch_one.return_value = {
                "user_id": "usr-001",
                "email": "john.doe@example.com"
            }

            result = await request_password_reset("john.doe@example.com")

            assert result["success"] is True
            assert "reset_token" in result

    @pytest.mark.asyncio
    async def test_reset_password_with_token(self):
        """Test resetting password with valid token."""
        from services.user_management.main import reset_password

        with patch('services.user_management.main.validate_reset_token') as mock_validate, \
             patch('services.user_management.main.hash_password') as mock_hash, \
             patch('services.user_management.main.db_manager') as mock_db:

            mock_validate.return_value = {"user_id": "usr-001"}
            mock_hash.return_value = "new_hashed"
            mock_db.fetch_one.return_value = {"user_id": "usr-001"}

            result = await reset_password("valid_token", "NewSecurePass123!")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(self):
        """Test password reset fails with invalid token."""
        from services.user_management.main import reset_password

        with patch('services.user_management.main.validate_reset_token') as mock_validate:
            mock_validate.return_value = None

            result = await reset_password("invalid_token", "NewPass123!")

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_password_complexity_validation(self):
        """Test password complexity validation."""
        from services.user_management.main import validate_password_complexity

        # Valid password
        assert validate_password_complexity("SecurePass123!") is True

        # Too short
        assert validate_password_complexity("Short1!") is False

        # No digit
        assert validate_password_complexity("NoDigitPassword!") is False

        # No special char
        assert validate_password_complexity("NoSpecialChar123") is False


class TestSessionManagement:
    """Test session management operations."""

    @pytest.mark.asyncio
    async def test_create_user_session(self):
        """Test creating user session."""
        from services.user_management.main import create_session

        user_id = "usr-001"

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await create_session(user_id)

            assert "session_id" in result
            assert result["user_id"] == user_id

    @pytest.mark.asyncio
    async def test_validate_session(self):
        """Test validating session."""
        from services.user_management.main import validate_session

        session_id = "sess-001"

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "session_id": session_id,
                "user_id": "usr-001",
                "expires_at": datetime.now() + timedelta(hours=1)
            }

            result = await validate_session(session_id)

            assert result is not None
            assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_validate_expired_session(self):
        """Test expired session is invalid."""
        from services.user_management.main import validate_session

        session_id = "sess-001"

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "session_id": session_id,
                "user_id": "usr-001",
                "expires_at": datetime.now() - timedelta(hours=1)
            }

            result = await validate_session(session_id)

            assert result is None or result.get("valid") is False

    @pytest.mark.asyncio
    async def test_invalidate_session(self):
        """Test invalidating session."""
        from services.user_management.main import invalidate_session

        session_id = "sess-001"

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await invalidate_session(session_id)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_invalidate_all_user_sessions(self):
        """Test invalidating all user sessions."""
        from services.user_management.main import invalidate_user_sessions

        user_id = "usr-001"

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await invalidate_user_sessions(user_id)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_active_sessions(self):
        """Test getting active user sessions."""
        from services.user_management.main import get_active_sessions

        user_id = "usr-001"

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_all.return_value = [
                {"session_id": "sess-001", "created_at": datetime.now()},
                {"session_id": "sess-002", "created_at": datetime.now()}
            ]

            sessions = await get_active_sessions(user_id)

            assert len(sessions) == 2


class TestUserPermissions:
    """Test user permission management."""

    @pytest.mark.asyncio
    async def test_grant_custom_permission(self):
        """Test granting custom permission to user."""
        from services.user_management.main import grant_permission

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {"user_id": "usr-001"}

            result = await grant_permission("usr-001", "alert.delete")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_revoke_permission(self):
        """Test revoking permission from user."""
        from services.user_management.main import revoke_permission

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await revoke_permission("usr-001", "alert.delete")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_user_permissions(self):
        """Test getting user permissions."""
        from services.user_management.main import get_user_permissions

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_all.return_value = [
                {"permission": "alert.read"},
                {"permission": "alert.update"},
                {"permission": "triage.create"}
            ]

            permissions = await get_user_permissions("usr-001")

            assert len(permissions) == 3
            assert "alert.read" in permissions


class TestUserActivity:
    """Test user activity tracking."""

    @pytest.mark.asyncio
    async def test_record_login(self):
        """Test recording user login."""
        from services.user_management.main import record_login

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await record_login(
                user_id="usr-001",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_record_logout(self):
        """Test recording user logout."""
        from services.user_management.main import record_logout

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await record_logout(session_id="sess-001")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_user_activity_log(self):
        """Test getting user activity log."""
        from services.user_management.main import get_user_activity_log

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_all.return_value = [
                {
                    "action": "login",
                    "timestamp": datetime.now() - timedelta(hours=2),
                    "ip_address": "192.168.1.100"
                },
                {
                    "action": "alert_viewed",
                    "timestamp": datetime.now() - timedelta(hours=1),
                    "ip_address": "192.168.1.100"
                }
            ]

            activities = await get_user_activity_log("usr-001", days=7)

            assert len(activities) == 2


class TestUserPreferences:
    """Test user preference management."""

    @pytest.mark.asyncio
    async def test_update_user_preferences(self):
        """Test updating user preferences."""
        from services.user_management.main import update_preferences

        preferences = {
            "theme": "dark",
            "notifications": {
                "email": True,
                "slack": False
            },
            "timezone": "America/New_York"
        }

        with patch('services.user_management.main.db_manager') as mock_db:
            result = await update_preferences("usr-001", preferences)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_user_preferences(self):
        """Test getting user preferences."""
        from services.user_management.main import get_preferences

        with patch('services.user_management.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "preferences": {
                    "theme": "dark",
                    "notifications": {"email": True}
                }
            }

            prefs = await get_preferences("usr-001")

            assert prefs["theme"] == "dark"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
