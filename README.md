# Mua-Backend Documentation and Integration Guide

The `mua-backend` is a full authentication and user management system designed to integrate seamlessly with the `mua-frontend`. It enables a Slack-like authentication experience, supporting multiple workspaces where users can log in with shared or separate credentials per workspace.

This backend simplifies the creation and management of accounts, users, and system administrators, providing ready-to-use routes.



## Features
- **Slack-like Workspace Management**: Users can log into separate workspaces with independent or shared credentials.
- **Route Auto-Generation**: Automatically generates routes for account, user, and system admin management.
- **Flexible API Integration**: Built to work with an API server created using the Express Async API.

## Getting Started
### Installation
Install mua-backend via npm:

```sh
npm install mua-backend
```

## Setup
To set up the `mua-backend`, you need to provide the following parameters:

1. `API Server`

- An instance created using the [express-async-api library](https://www.npmjs.com/package/express-async-api).

2. `Models`

- **AccountModel**: The model for managing workspace accounts.
- **UserModel**: The model for managing users.
- **SystemAdminModel**: The model for managing system administrators.


```javascript

import MuaBackend from'mua-backend' 
import AccountModel from'./models/account' 
import UserModel from'./models/user'
import SystemAdminModel from'./models/systemAdmin' 

MuaBackend({  
  apiServer,  
  AccountModel,
  UserModel,
  SystemAdminModel  
})

```
3. Add to `.env` file

```bash
NODE_ENV=development
SECRETS=testsecret1 testsecret2

APP_URL=<app_url>

BLUEFOX_TRANSACTIONAL_EMAIL_API_URL=<emailfox_transactional_url>

BLUEFOX_API_KEY=<bluefox_email_api_key>

BLUEFOX_TEMPLATE_ID_ADMIN_VERIFY_EMAIL=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ADMIN_FORGOT_PASSWORD=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ADMIN_INVITATION=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ACCOUNT_FINALIZE_REGISTRATION=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ACCOUNT_FORGOT_PASSWORD=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ACCOUNT_INVITATION=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ACCOUNT_LOGIN_SELECT=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ACCOUNT_VERIFY_EMAIL=<bluefox_template_id>
BLUEFOX_TEMPLATE_ID_ACCOUNT_CREATE_PASSWORD=<bluefox_template_id>

TEST_STATIC_SERVER_URL=<test_static_server_url>
CDN_BASE_URL=<cdn_base_url>

AWS_BUCKET_PATH=<aws.bucket.path>
AWS_BUCKET_NAME=<your_aws_bucket_name>
AWS_FOLDER_NAME=<your_aws_folder_name>
AWS_REGION=<your_aws_region>
AWS_ACCESS_KEY_ID=<your_aws_access_key_id>
AWS_SECRET_ACCESS_KEY=<your_aws_secret_access_key>

ALPHA_MODE=false
MAX_FILE_SIZE=5242880

GOOGLE_CLIENT_ID=<your_google_client_id>
GOOGLE_CLIENT_SECRET=<your_google_secret_access_key>

MICROSOFT_CLIENT_ID=<your_microsoft_client_id>
MICROSOFT_CLIENT_SECRET=<your_microsoft_secret_access_key>

GITHUB_CLIENT_ID=<your_github_client_id>
GITHUB_CLIENT_SECRET=<your_github_secret_access_key>

```

## API Routes

The following table outlines the automatically generated routes and their purposes:

### Accounts routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/create`                                       | POST    | Create an account.                                    |
| `/v1/accounts/`                                             | POST    | Create a new account by admin.                                 |
| `/v1/accounts/:id/logo`                                     | POST    | Upload account logo.                                  |
| `/v1/accounts/permission/:permissionFor`                    | POST    | Assign permission to an account.                      |
| `/v1/accounts/`                                             | GET     | Retrieve all accounts.                               |
| `/v1/accounts/:id`                                          | GET     | Retrieve account by ID.                               |
| `/v1/accounts/by-url-friendly-name/:urlFriendlyName`        | GET     | Retrieve account by URL-friendly name.                |
| `/v1/accounts/check-availability`                           | GET     | Check if account is available pass urlFriendlyName in query.  |
| `/v1/accounts/:id/name`                                     | PATCH   | Update account name.                                  |
| `/v1/accounts/:id/urlFriendlyName`                          | PATCH   | Update account URL-friendly name.                     |
| `/v1/accounts/:id/logo`                                     | DELETE  | Delete account logo.                                  |
| `/v1/accounts/:id`                                          | DELETE  | Delete an account.                                    |

### System admins routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/system-admins/permission/:permissionFor`               | POST    | Assign permission to a system admin.                  |
| `/v1/system-admins/:id/profile-picture`                     | POST    | Upload system admin profile picture.                  |
| `/v1/system-admins/`                                        | GET     | Retrieve all system admins.                           |
| `/v1/system-admins/:id`                                     | GET     | Retrieve system admin by ID.                          |
| `/v1/system-admins/:id/access-token`                        | GET     | Retrieve access token for a system admin.             |
| `/v1/system-admins/:id/name`                                | PATCH   | Update system admin name.                             |
| `/v1/system-admins/:id/password`                            | PATCH   | Update system admin password.                         |
| `/v1/system-admins/:id/email`                               | PATCH   | Update system admin email.                            |
| `/v1/system-admins/:id/email-confirm`                       | PATCH   | Confirm system admin email.                           |
| `/v1/system-admins/:id/profile-picture`                     | DELETE  | Delete system admin profile picture.                  |
| `/v1/system-admins/:id`                                     | DELETE  | Delete a system admin.                                |

### Users routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:accountId/users`                             | POST    | Create a new user in account.                         |
| `/v1/accounts/:accountId/users/:id/profile-picture`         | POST    | Upload user profile picture.                         |
| `/v1/accounts/:accountId/users`                             | GET     | Retrieve all users in account.                        |
| `/v1/accounts/:accountId/users/:id`                         | GET     | Retrieve user by ID in account.                       |
| `/v1/accounts/:accountId/users/:id/name`                    | PATCH   | Update user name in account.                          |
| `/v1/accounts/:accountId/users/:id/password`                | PATCH   | Update user password.                                 |
| `/v1/accounts/:accountId/users/:id/email`                   | PATCH   | Update user email.                                    |
| `/v1/accounts/:accountId/users/:id/create-password`         | PATCH   | Create password for user.                             |
| `/v1/accounts/:accountId/users/:id/email-confirm`           | PATCH   | Confirm user email.                                   |
| `/v1/accounts/:accountId/users/:id/profile-picture`         | DELETE  | Delete user profile picture.                         |
| `/v1/accounts/:accountId/users/:id`                         | DELETE  | Delete a user in account.                             |

### Auth routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:id/login`                                    | POST    | Log in to an account.                                 |
| `/v1/accounts/:id/login/url-friendly-name`                  | POST    | Log in using URL-friendly name.                       |
| `/v1/accounts/login`                                        | POST    | Log in to any account.                                |
| `/v1/system-admins/login`                                   | POST    | Log in as system admin.                               |
| `/v1/accounts/:accountId/users/:id/finalize-registration`   | POST    | Finalize user registration in account.                |
| `/v1/accounts/:accountId/users/:userId/resend-finalize-registration` | POST | Resend finalize registration for a user.        |
| `/v1/accounts/:accountId/users/:id/access-token`            | GET     | Retrieve user access token in account.                |

### Provider Auth routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:accountId/users/:id/link/provider/:provider` | POST    | Link user to a provider (e.g., Google).                |
| `/v1/accounts/create-account/provider/:provider`            | POST    | Create an account via third-party provider.            |
| `/v1/accounts/:id/login/provider/:provider`                 | POST    | Log in via third-party provider (e.g., Google).        |
| `/v1/accounts/provider/google/callback`                     | GET     | Google OAuth callback.                                |
| `/v1/accounts/provider/microsoft/callback`                  | GET     | Microsoft OAuth callback.                             |
| `/v1/accounts/provider/github/callback`                     | GET     | GitHub OAuth callback.                                |
| `/v1/accounts/:accountId/users/:id/provider/:provider`      | PATCH   | Update user provider link.                           |


### Forgot password routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:id/forgot-password/send`                     | POST    | Send password reset email for account.                |
| `/v1/system-admins/forgot-password/send`                    | POST    | Send password reset email for system admin.           |
| `/v1/accounts/:id/forgot-password/reset`                    | POST    | Reset account password.                               |
| `/v1/system-admins/forgot-password/reset`                   | POST    | Reset system admin password.                          |


### Invitation routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:id/invitation/send`                          | POST    | Send invitation for account.                          |
| `/v1/system-admins/invitation/send`                         | POST    | Send invitation for system admin.                     |
| `/v1/accounts/:id/invitation/resend`                        | POST    | Resend account invitation.                            |
| `/v1/system-admins/invitation/resend`                       | POST    | Resend system admin invitation.                       |
| `/v1/accounts/:id/invitation/accept`                        | POST    | Accept account invitation.                            |
| `/v1/system-admins/invitation/accept`                       | POST    | Accept system admin invitation.                       |




### Statistics routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/statistics/accounts/`                                  | GET     | Retrieve statistics for accounts.                     |
| `/v1/statistics/users/`                                     | GET     | Retrieve statistics for users.                        |
