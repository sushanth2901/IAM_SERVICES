import tempfile

from flask import Flask, request, jsonify, send_file
import boto3
from botocore.exceptions import ClientError
import json
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize Boto3 IAM client
iam = boto3.client('iam')

@app.route('/')
def index():
    return "AWS IAM Management API"

# Endpoint to create an IAM role
@app.route('/create_role', methods=['POST'])
def create_role():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            role_data = json.load(file)
            if not isinstance(role_data, list):
                return jsonify({'error': 'Invalid JSON format. Expected a list of roles'}), 400

            created_roles = []
            errors = []

            for role in role_data:
                role_name = role.get('role_name')
                assume_role_policy_document = json.dumps(role.get('assume_role_policy_document'))

                if not role_name or not assume_role_policy_document:
                    errors.append({'role': role, 'error': 'Missing role_name or assume_role_policy_document'})
                    continue

                try:
                    response = iam.create_role(
                        RoleName=role_name,
                        AssumeRolePolicyDocument=assume_role_policy_document
                    )
                    created_roles.append(response)
                except ClientError as e:
                    errors.append({'role_name': role_name, 'error': str(e)})

            if errors:
                return jsonify({'created_roles': created_roles, 'errors': errors, 'message': 'Some roles were not created successfully.'}), 207
            return jsonify({'created_roles': created_roles, 'message': 'All roles created successfully.'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Endpoint to delete an IAM role
@app.route('/delete_role', methods=['POST'])
def delete_role():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            role_data = json.load(file)
            if not isinstance(role_data, list):
                return jsonify({'error': 'Invalid JSON format. Expected a list of roles'}), 400

            deleted_roles = []
            errors = []

            for role in role_data:
                role_name = role.get('role_name')

                if not role_name:
                    errors.append({'role': role, 'error': 'Missing role_name'})
                    continue

                try:
                    response = iam.delete_role(
                        RoleName=role_name
                    )
                    deleted_roles.append(response)
                except ClientError as e:
                    errors.append({'role_name': role_name, 'error': str(e)})

            if errors:
                return jsonify({'deleted_roles': deleted_roles, 'errors': errors, 'message': 'Some roles were not deleted successfully.'}), 207
            return jsonify({'deleted_roles': deleted_roles, 'message': 'All roles deleted successfully.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Endpoint to attach a policy to a role
@app.route('/attach_policy', methods=['POST'])
def attach_policy():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            attach_data = json.load(file)
            if not isinstance(attach_data, list):
                return jsonify({'error': 'Invalid JSON format. Expected a list of attachments'}), 400

            attached_policies = []
            errors = []

            for attach in attach_data:
                role_name = attach.get('role_name')
                policy_arn = attach.get('policy_arn')

                if not role_name or not policy_arn:
                    errors.append({'attach': attach, 'error': 'Missing role_name or policy_arn'})
                    continue

                try:
                    response = iam.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy_arn
                    )
                    attached_policies.append(response)
                except ClientError as e:
                    errors.append({'role_name': role_name, 'error': str(e)})

            if errors:
                return jsonify({'attached_policies': attached_policies, 'errors': errors, 'message': 'Some policies were not attached successfully.'}), 207
            return jsonify({'attached_policies': attached_policies, 'message': 'All policies attached successfully.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Endpoint to detach a policy from a role
@app.route('/detach_policy', methods=['POST'])
def detach_policy():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            detach_data = json.load(file)
            if not isinstance(detach_data, list):
                return jsonify({'error': 'Invalid JSON format. Expected a list of detachments'}), 400

            detached_policies = []
            errors = []

            for detach in detach_data:
                role_name = detach.get('role_name')
                policy_arn = detach.get('policy_arn')

                if not role_name or not policy_arn:
                    errors.append({'detach': detach, 'error': 'Missing role_name or policy_arn'})
                    continue

                try:
                    response = iam.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy_arn
                    )
                    detached_policies.append(response)
                except ClientError as e:
                    errors.append({'role_name': role_name, 'error': str(e)})

            if errors:
                return jsonify({'detached_policies': detached_policies, 'errors': errors, 'message': 'Some policies were not detached successfully.'}), 207
            return jsonify({'detached_policies': detached_policies, 'message': 'All policies detached successfully.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        user_name = request.form['user_name']
        password = request.form['password']
        # Optionally handle other form data or file upload if needed

        # Create IAM user with initial password
        response = iam.create_user(UserName=user_name)

        # Set initial password for the user
        iam.create_login_profile(UserName=user_name, Password=password, PasswordResetRequired=True)

        return jsonify({'message': 'User created successfully'}), 201
    except ClientError as e:
        return jsonify({'error': str(e)}), 400


# Endpoint to delete an IAM user
@app.route('/delete_user', methods=['POST'])
def delete_user():
    try:
        user_name = request.form['user_name']
        # Optionally handle other form data or file upload if needed

        # Delete IAM user
        response = iam.delete_user(UserName=user_name)

        return jsonify({'message': 'User deleted successfully'}), 200
    except ClientError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/create_user_from_file', methods=['POST'])
def create_user_from_file():
    try:
        file = request.files['file']
        if not file:
            return jsonify({'error': 'No file uploaded'}), 400

        # Load JSON data from file
        users = json.load(file)
        if not isinstance(users, list):
            return jsonify(
                {'error': 'Invalid JSON format. Expected a list of user objects with "user_name" keys.'}), 400

        created_users = []
        errors = []

        for user_data in users:
            user_name = user_data.get('user_name')
            if not user_name:
                errors.append({'user_data': user_data, 'error': 'Missing "user_name" key'})
                continue

            try:
                response = iam.create_user(
                    UserName=user_name
                )
                created_users.append({'user_name': user_name, 'message': 'User created successfully'})
            except ClientError as e:
                errors.append({'user_name': user_name, 'error': str(e)})

        return jsonify({'created_users': created_users, 'errors': errors}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Endpoint to download credentials
@app.route('/download_credentials', methods=['GET'])
def download_credentials():
    try:
        # Generate temporary credentials file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Simulated content for credentials (replace with actual logic to generate credentials)
            temp_file.write(b"AccessKey=exampleAccessKey\nSecretKey=exampleSecretKey")
            temp_file.close()
            temp_filename = temp_file.name

        # Serve the file for download
        return send_file(temp_filename, as_attachment=True, download_name='credentials.txt')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
