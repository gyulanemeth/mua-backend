# Mua-Backend Documentation and Integration Guide

The `mua-backend` is a full authentication and user management system designed to integrate seamlessly with the `mua-frontend`. It enables a Slack-like authentication experience, supporting multiple workspaces where users can log in with shared or separate credentials per workspace.

This backend simplifies the creation and management of accounts, users, and system administrators, providing ready-to-use routes.



## Features
- **Slack-like Workspace Management**: Users can log into separate workspaces, each with its own independent credentials.
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

- To ensure smooth integration and customization, it's essential that you pass the following models to the `mua-backend`. These models define the mandatory properties that are needed for managing accounts, users, and system administrators. You can extend these models by adding additional properties as needed.

- **AccountModel**: The model for managing workspace accounts.
```javascript

const AccountSchema = new mongoose.Schema({
  name: { type: String },
  urlFriendlyName: { type: String, unique: true },
  logo: { type: String },
  deleted: { type: Boolean }
}, { timestamps: true })

export default mongoose.model('Account', AccountSchema)

```
- **UserModel**: The model for managing users.

```javascript

const UserProjectAccessSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  permission: { type: String, enum: ['viewer', 'editor'], required: true }
}, { _id: false })

const UserSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/ },
  password: { type: String },
  googleProfileId: { type: String },
  microsoftProfileId: { type: String },
  githubProfileId: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin', 'client'] },
  projectsAccess: { type: [UserProjectAccessSchema], default: [] },
  accountId: { type: Schema.Types.ObjectId, ref: 'Account', required: true },
  profilePicture: { type: String },
  verified: { type: Boolean, default: false },
  deleted: { type: Boolean },
  twoFactor: {
    enabled: { type: Boolean, default: false },
    secret: { type: String },
    recoverySecret: { type: String }
  }
}, { timestamps: true })

export default mongoose.model('User', UserSchema)

```

- **ProjectModel**: The model for client users project access permission level.

```javascript

const ProjectSchema = new mongoose.Schema({
  name: { type: String },
  accountId: { type: Schema.Types.ObjectId, ref: 'Account', required: true }
}, { timestamps: true })

export default mongoose.model('Project', ProjectSchema)

```
- **SystemAdminModel**: The model for managing system administrators.

```javascript

const SystemAdminSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String },
  twoFactor: {
    enabled: { type: Boolean, default: false },
    secret: { type: String },
    recoverySecret: { type: String }
  }
}, { timestamps: true });

export default mongoose.model('SystemAdmin', SystemAdminSchema)

```

3. Integration Example

```javascript

import MuaBackend from'mua-backend' 
import AccountModel from'./models/account' 
import UserModel from'./models/user'
import SystemAdminModel from'./models/systemAdmin' 
import ProjectModel from'./models/project' 

MuaBackend({  
  apiServer,  
  AccountModel,
  UserModel,
  SystemAdminModel,
  ProjectModel
  hooks: {} // optional  
})

```
4. Add to `.env` file

You need to provide the following environment variables in a .env file for Mua to function properly.

```bash
NODE_ENV=development # Environment mode (e.g., development, production)
SECRETS=testsecret1 testsecret2 # Space-separated list of secrets used for token encryption

ENCRYPTION_SECRET_KEY=<app_name> # Your 2FA secrets will be encrypted in db using this key

APP_NAME=<app_name> # Your app name (will show it 2FA)

APP_URL=<app_url> # The base URL of your application

BLUEFOX_TRANSACTIONAL_EMAIL_API_URL=<emailfox_transactional_url> # URL for the Bluefox transactional email API
BLUEFOX_API_KEY=<bluefox_email_api_key> # API key for Bluefox email service

BLUEFOX_TEMPLATE_ID_ADMIN_VERIFY_EMAIL=<bluefox_template_id> # Bluefox Template ID for admin email verification
BLUEFOX_TEMPLATE_ID_ADMIN_FORGOT_PASSWORD=<bluefox_template_id> # Bluefox Template ID for admin forgot password
BLUEFOX_TEMPLATE_ID_ADMIN_INVITATION=<bluefox_template_id> # Bluefox Template ID for admin invitation
BLUEFOX_TEMPLATE_ID_ACCOUNT_FINALIZE_REGISTRATION=<bluefox_template_id> # Bluefox Template ID for account registration finalization
BLUEFOX_TEMPLATE_ID_ACCOUNT_FORGOT_PASSWORD=<bluefox_template_id> # Bluefox Template ID for account forgot password
BLUEFOX_TEMPLATE_ID_ACCOUNT_INVITATION=<bluefox_template_id> # Bluefox Template ID for account invitation
BLUEFOX_TEMPLATE_ID_ACCOUNT_LOGIN_SELECT=<bluefox_template_id> # Bluefox Template ID for account login selection
BLUEFOX_TEMPLATE_ID_ACCOUNT_VERIFY_EMAIL=<bluefox_template_id> # Bluefox Template ID for account email verification
BLUEFOX_TEMPLATE_ID_ACCOUNT_CREATE_PASSWORD=<bluefox_template_id> # Bluefox Template ID for account password creation

CDN_BASE_URL=<cdn_base_url> # Base URL for your CDN

AWS_BUCKET_PATH=<aws.bucket.path> # Path to the AWS bucket
AWS_BUCKET_NAME=<your_aws_bucket_name> # Name of the AWS S3 bucket
AWS_FOLDER_NAME=<your_aws_folder_name> # Folder name in the AWS S3 bucket
AWS_REGION=<your_aws_region> # AWS region for the S3 bucket
AWS_ACCESS_KEY_ID=<your_aws_access_key_id> # AWS access key ID
AWS_SECRET_ACCESS_KEY=<your_aws_secret_access_key> # AWS secret access key

ALPHA_MODE=false # Enable alpha mode (true/false)
MAX_FILE_SIZE=5242880 # Maximum file upload size in bytes (e.g., 5MB)

GOOGLE_CLIENT_ID=<your_google_client_id> # Google OAuth client ID
GOOGLE_CLIENT_SECRET=<your_google_client_secret> # Google OAuth client secret

MICROSOFT_CLIENT_ID=<your_microsoft_client_id> # Microsoft OAuth client ID
MICROSOFT_CLIENT_SECRET=<your_microsoft_client_secret> # Microsoft OAuth client secret

GITHUB_CLIENT_ID=<your_github_client_id> # GitHub OAuth client ID
GITHUB_CLIENT_SECRET=<your_github_client_secret> # GitHub OAuth client secret

```

### Customization

The `mua-backend` allows users to customize behavior after specific actions, such as creating or deleting accounts. Pass a `hooks` object with functions to override default behaviors:

```javascript

MuaBackend({
  apiServer,
  AccountModel,
  UserModel,
  SystemAdminModel,
  ProjectModel,
  hooks: {
    checkEmail: async (params) => {
      // Custom logic for checking email before creating or patching user or system admin (if you want to prevent spicific email you can throw error insde here for example disposable email and this will prevent the creation / update of the user email)
    },
    deleteAccount: {
      post: (params) => {
        // Custom logic after deleting an account
      },
    },
    createAccount: {
      post: (params) => {
        // Custom logic after creating an account
      },
    },
    createNewUser: {
      post: (params) => {
        // Custom logic after creating a new user
      },
    },
    updateUserEmail: {
      post: (params) => {
        // Custom logic after updating a user's email
      },
    },
  },
})

```

Each hook accepts an object with a `post` method that executes custom logic after the associated action is completed.

## 📧 Email Templates – Available Merge Tags

This section documents the available merge tags for each BlueFox email template.  
Merge tags are dynamic placeholders that will be replaced with actual values when the email is sent.

## 🔐 Admin Templates

### Invitation
**Merge Tags:**
- `{{inviter.name}}` – Invited admin name
- `{{link}}` – button link
---

### Change email address
**Merge Tags:**
- `{{name}}` – Admin name
- `{{link}}` – button link
---

### Forgot password
**Merge Tags:**
- `{{name}}` – Admin name
- `{{link}}` – button link
---


## 👤 Account Templates

### Select account
**Merge Tags:**
- `{{link}}` – button link
---

### Invitation
**Merge Tags:**
- `{{accountName}}` – Account name
- `{{inviter}}` – Inviter name
- `{{link}}` – button link
---

### Finalize registration
**Merge Tags:**
- `{{name}}` – User name
- `{{link}}` – button link
---

### Change email address
**Merge Tags:**
- `{{name}}` – User name
- `{{link}}` – button link
---

### Add password
**Merge Tags:**
- `{{name}}` – User name
- `{{link}}` – button link
---

### Forgot password
**Merge Tags:**
- `{{name}}` – User name
- `{{link}}` – button link

## API Routes

Developers using mua can rely on the seamless integration with the mua-frontend, so they don't need to concern themselves with these routes. The table below outlines the automatically generated routes and their purposes:

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
| `/v1/system-admins/:id/mfa`                                 | GET     | Get 2FA Qr and code.                                  |
| `/v1/system-admins/:id/mfa`                                 | POST    | Confirm and enable system admin 2FA.                  |
| `/v1/system-admins/:id/mfa`                                 | DELETE  | Disable system admin 2FA.                             |

### Users routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:accountId/users`                             | POST    | Create a new user in account.                         |
| `/v1/accounts/:accountId/users/:id/profile-picture`         | POST    | Upload user profile picture.                          |
| `/v1/accounts/:accountId/projects-for-access`               | GET     | Retrieve all account projects.                        |
| `/v1/accounts/:accountId/users`                             | GET     | Retrieve all users in account.                        |
| `/v1/accounts/:accountId/users/:id`                         | GET     | Retrieve user by ID in account.                       |
| `/v1/accounts/:accountId/users/:id/name`                    | PATCH   | Update user name in account.                          |
| `/v1/accounts/:accountId/users/:id/password`                | PATCH   | Update user password.                                 |
| `/v1/accounts/:accountId/users/:id/email`                   | PATCH   | Update user email.                                    |
| `/v1/accounts/:accountId/users/:id/create-password`         | PATCH   | Create password for user.                             |
| `/v1/accounts/:accountId/users/:id/email-confirm`           | PATCH   | Confirm user email.                                   |
| `/v1/accounts/:accountId/users/:id/profile-picture`         | DELETE  | Delete user profile picture.                          |
| `/v1/accounts/:accountId/users/:id`                         | DELETE  | Delete a user in account.                             |
| `/v1/accounts/:accountId/users/:id/mfa`                     | GET     | Get 2FA Qr and code.                                  |
| `/v1/accounts/:accountId/users/:id/mfa`                     | POST    | Confirm and enable user 2FA.                          |
| `/v1/accounts/:accountId/users/:id/mfa`                     | DELETE  | Disable user 2FA.                                     |

### Auth routes

| Route                                                       | Method  | Description                                           |
|-------------------------------------------------------------|---------|-------------------------------------------------------|
| `/v1/accounts/:id/login`                                    | POST    | Log in to an account.                                 |
| `/v1/accounts/:id/login/url-friendly-name`                  | POST    | Log in using URL-friendly name.                       |
| `/v1/accounts/login`                                        | POST    | Log in to any account.                                |
| `/v1/accounts/mfa-login`                                    | POST    | Enter 2FA code or recovery code to login              |
| `/v1/system-admins/login`                                   | POST    | Log in as system admin.                               |
| `/v1/system-admins/mfa-login`                               | POST    | Enter 2FA code or recovery code to login              |
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




