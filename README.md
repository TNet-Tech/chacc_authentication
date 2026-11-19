# Authentication Module

A ChaCC API module providing user authentication and management functionality.

## Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- User profile management
- Admin user listing
- Service registration for other modules

## Development

### Environment Setup

```bash
cd plugins/authentication
python module/run_tests.py setup
```

This creates a virtual environment and installs dependencies.

### Running Tests

```bash
# With venv
python module/run_tests.py test

# Without venv
python module/run_tests.py test --no-venv
```

### Standalone Development

Run the module independently for development:

```bash
python module/run_tests.py standalone
```

The module will be available at `http://localhost:8001/auth/`

### Environment Variables

- `SECRET_KEY`: JWT secret key (use strong key in production)
- `AUTHENTICATION_ENABLE_SELF_REGISTRATION`: set to `True` or `False` to allow user to selft-register

# -----------------------------------------------------------------
# Default Admin User  (used by the official chacc-auth module only)
# -----------------------------------------------------------------
- `AUTHENTICATION_DEFAULT_ADMIN_USERNAME`: set username for automatic created account
- `AUTHENTICATION_DEFAULT_ADMIN_PASSWORD`: set password for automatic created account
- `AUTHENTICATION_ACCESS_TOKEN_EXPIRE_MINUTES`: access token lifetime in minutes (default 10)
- `AUTHENTICATION_REFRESH_TOKEN_EXPIRE_MINUTES`: refresh token lifetime in minutes (default 15)


## API Endpoints

### Authentication
- `POST /register` - Register new user
- `POST /login` - Login and get JWT token

### User Management
- `GET /me` - Get current user profile
- `PUT /me` - Update current user profile
- `DELETE /me` - Delete current user account
- `GET /users` - Admin: List all users

## Module Structure

```
module/
├── __init__.py
├── main.py          # Module setup
├── models.py        # Database models and schemas
├── routes.py        # API endpoints
├── auth.py          # Authentication utilities
├── dev_context.py   # Development context mock
├── context_factory.py # Context provider
├── tests/
│   └── test_module.py
└── run_tests.py     # Development tools
```

## Context Access

The module uses a context factory to work in different environments:

- **Development**: Uses provided BackboneContext
- **Production**: Uses provided BackboneContext
- **Testing**: Minimal context for isolated testing

## Module Dependencies

This module depends on no other ChaCC module (`module_dependencies` in
`module_meta.json` is empty). Other modules depend on it:

| Module | Kind | Uses |
| --- | --- | --- |
| `chacc_menu` | required | `get_current_user`, `privilege_service`, `has_privileges`, and the `users` table (foreign keys) |
| `chacc_outbound` | optional | `get_current_user` |

chacc-api loads this module before the modules that require it, so its services
are registered by the time their `setup_plugin` runs.

## Services Provided

Get them with `context.get_service("<name>")`. These names are the module's
public contract: renaming or removing one breaks the modules listed above.

| Service | What it is |
| --- | --- |
| `get_current_user` | `async (credentials) -> User \| None`: resolves the user from a Bearer token, for protecting routes in other modules |
| `UserModel` | The `User` SQLAlchemy model |
| `get_password_hash` | Hashes a plain-text password |
| `privilege_service` | `PrivilegeService`: modules register their own privileges with `await privilege_service.ensure([(name, description, level), ...])` |
| `has_privileges` | `async (credentials, privilege_names, *, require_all=False) -> User`: raises 401/403 when the user lacks the privileges |

## Dependencies

- fastapi
- sqlalchemy
- passlib[bcrypt]
- python-jose[cryptography]
- pydantic