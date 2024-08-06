# Flask Assignment
In this Flask assignment, a robust user management system has been created using Python and Flask. It includes routes for user registration, sign-in, password reset, and both updating and deleting user accounts. The application uses JWTs for secure authentication and password hashing for protecting user credentials. Environmental variables are utilized for sensitive database configuration to ensure security and flexibility. This setup allows for efficient user management and secure access control in a web application.

### Technology Stack

As the name suggests, this repository is built on top of Python,Flask & PostgreSQL, however, in the implementation detail, we will find other supporting technologies as well.

<img src="https://img.shields.io/badge/PostgreSQL-%2331575F?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" width="60" height="20"/>: For the database to store user information, complaints, and other relevant data.

<img src="https://img.shields.io/badge/Python-%233776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" width="60" height="20"/>: The programming language used to build the application.

<img src="https://img.shields.io/badge/Flask-%23000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" width="60" height="20"/>: The web framework used to build the backend of the application.

<img src="https://img.shields.io/badge/Postman-%23FF6C37?style=for-the-badge&logo=postman&logoColor=white" alt="Postman" width="60" height="20"/>: For testing API endpoints and ensuring smooth communication between frontend and backend.





### Running the Project
Before running the application, make sure you have installed python in your machine.

1. Clone the project
    ```bash
    git clone https://github.com/Md-Roni024/Flask_API_Assignment
    ```  

2. Go to the project directory and setup virtual environment
    ```
    cd Flask_API_Assignment
    python -m venv venv
    .\venv\Scripts\activate
    ```

3. Install dependencies
    ```
    pip install -r requirements.txt
    ```

4. Create a .env file then add your variables credentials as like:
    ```
    DATABASE_USER=""
    DATABASE_PASSWORD=""
    DATABASE_HOST=""
    DATABASE_NAME=""

    //Server Listening PORT
    PORT = ""
    ```
5. Start the project
    ```
    python run.py
    ```
    After successfully run the project it will launch in port 5000. and Root URL will be : http://127.0.0.1:5000


### REST API
For managing user information I build 5 endpoints.They are responsible for register,signin,reset-password,update user and delete user. 

- <h3>Create a new USER</h3>
  <h5>Content-Type: application/json</h5>
  <h5>Method: POST</h5>
  <h5>URL: http://127.0.0.1:5000/register</h5>

  Test Input:
  
  ```json
        {
            "username": "test33",
            "first_name": "Roni",
            "last_name": "Hossain",
            "email": "test33@example.com",
            "password": "12345678",
            "role": "User",
            "active": true
        }

  ```
  Success Response:
  ```json
    {
    "message": "User created",
    "user": {
        "active": true,
        "created_date": "2024-08-05T07:00:49.586343",
        "email": "test33@example.com",
        "first_name": "Roni",
        "id": 8,
        "last_name": "Hossain",
        "role": "USER",
        "updated_date": "2024-08-05T07:00:49.586343",
        "username": "test33"
        }
    }

  ```

  <h5>Status Code</h5>

    ```

    Success: 200 User Created
    Fail: 400 BAD REQUEST

    ```

- <h3>Get All User</h3>
  <h5>Content-Type: application/json</h5>
  <h5>Method: GET</h5>
  <h5>URL: http://127.0.0.1:5000/users</h5>
  <h5>Only Role: Admin user can have access this route</h5>
  Success Response:

  ```json
    {
    "message": "All Users",
    "user": [
        {
        "active": true,
        "created_date": "Mon, 05 Aug 2024 05:47:16 GMT",
        "email": "test@example.com",
        "first_name": "Roni",
        "id": 4,
        "last_name": "Hossain",
        "role": "ADMIN",
        "updated_date": "Mon, 05 Aug 2024 05:47:16 GMT",
        "username": "test1234"
        },
        {
        "active": true,
        "created_date": "Mon, 05 Aug 2024 05:58:34 GMT",
        "email": "hello@example.com",
        "first_name": "Roni",
        "id": 5,
        "last_name": "Hossain",
        "role": "ADMIN",
        "updated_date": "Mon, 05 Aug 2024 05:58:34 GMT",
        "username": "hello1234"
        }
      ]
    }

  ```
  <h5>Status Code</h5>

  ```
    Success: 200 OK
    Fail: 400 BAD REQUEST
  ```


- <h3>Get Single User By ID</h3>
  <h5>Content-Type: application/json</h5>
  <h5>Method: GET</h5>
  <h5>Role: Admin user can access anyone info, but Role:User who are logedin can access own info. </h5>
  <h5>URL: http://127.0.0.1:5000/users/9</h5>

  Success Response:
  ```json
        {
    "Message": "User by user id",
    "user": {
        "active": true,
        "created_date": "2024-08-05T07:24:02.947393",
        "email": "abdullah@example.com",
        "first_name": "Abdullah",
        "id": 9,
        "last_name": "Mamun",
        "role": "USER",
        "updated_date": "2024-08-05T07:24:02.947393",
        "username": "Abdullah"
        }
    }

  ```

  <h5>Status Code</h5>

    ```
    Success: 200 OK
    Fail: 
    404 NOT FOUND
    403	Forbidden
    404	User not found
    ```

- <h3>Delete User By ID</h3>
  <h5>Content-Type: application/json</h5>
  <h5>Method: DELETE</h5>
  <h5>URL: http://127.0.0.1:5000/users/7</h5>
  <h5>Only Role: Admin have access this route </h5>

  Success Response:
  ```json
    {
        "Message": "User deleted successfully"
    }

  ```

  <h5>Status Code</h5>

    ```
    
    Success: 200 OK
    Fail:
    404 NOT FOUND
    403	Forbidden
    ```


  - <h3>Update User By ID</h3>
  <h5>Content-Type: application/json</h5>
  <h5>Method: PUT</h5>
  <h5>URL: http://127.0.0.1:5000/users/7</h5>
  <h5>Role: Admin user can update anyone info, but Role:User who are logedin can update own info.</h5>

  Input:
  ```JSON
  {
    "first_name": "string",
    "last_name": "string",
    "email": "string",
    "role": "string"
  }
  ```

  Success Response:
  ```json
    {
    "id": 0,
    "username": "string",
    "first_name": "string",
    "last_name": "string",
    "email": "string",
    "role": "string",
    "created_date": "2024-08-06T07:26:33.031Z",
    "updated_date": "2024-08-06T07:26:33.031Z",
    "active": true
  }

  ```

  <h5>Status Code</h5>

    ```
    
    Success: 200 OK
    Fail:
    400	Bad request
    403	Forbidden
    404	User not found

    ```


- <h3>User Login</h3>
  <h5>Content-Type: application/json</h5>
  <h5>Method: POST</h5>
  <h5>URL: http://127.0.0.1:5000/login</h5>

  Test Unput:
  ```json        
  {
    "username": "Abdullah",
    "password":"12345678"
  }
  ```


  Success Response:
  ```json
    {
    "Message": "Login Successful",
    "Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyMjg0MzAzNCwianRpIjoiY2M4MWMwMzgtYjY5Zi00ZWVmLTk0MDMtNjRhM2Q5NmQ5ZTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6OSwibmJmIjoxNzIyODQzMDM0LCJjc3JmIjoiY2M3NjQ1MTctMWRmMy00ZTJhLTg2YjUtZjU5NWVhNjUyY2I5IiwiZXhwIjoxNzIyODQ2NjM0fQ.kyPvLUogU2znRNRPk91wkf3_wEeailXEF1OwETtHnN4"
    }

  ```

  <h5>Status Code</h5>

    ```
    
    Success: 200 OK
    Fail:
    401 UNAUTHORIZED
    401 Invalid credentials

    ```
- <h3>Reset password Request</h2>
  Method: POST

  URL: http://127.0.0.1:5000/register/reset-password-request


  Input Look likes:
  ```json
  {
    "username": "Abdullah"
  }
  ```
  If Username is correct then A token will send to user mail.

   <h5>Status Code</h5>

    ```
  Success:200 Password reset link sent
  Fail:
  400	Bad request
  404	User not found

  ```


- <h3>Reset-password after getting token</h2>
  Method: POST

  URL: http://127.0.0.1:5000/register/reset-password/{token}


  Input New Password Look likes:
  ```json
  {
    "new_password": "string"
  }
  ```

  If token is correct then password wil rest successfully.
     <h5>Status Code</h5>

    ```
  Success: 200	Password reset successful
  Fail:
  400 Invalid or expired token
  


### Design Database Schema
- Database Name: <span style="color:red;font-size:15px;font-weight:bold">hotel_db</span>

- Hotel Deatils Table
  ```sql
  CREATE TABLE hotel_details(
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      first_name VARCHAR(255) NOT NULL,
      last_name VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      role TEXT,
      created_date Date,
      updated_date Date,
      active boolean
  );

  ```

### Contributing
- Contributing is an open invitation for collaboration on the project. You're encouraged to participate by opening issues for bugs or feature requests and submitting pull requests with your improvements or fixes. Your contributions help enhance and grow the project, making it better for everyone.


### Contact

- For any questions or feedback, please reach out to me at roni.cse@gmail.com. I welcome all inquiries and look forward to hearing from you. Your input is valuable and appreciated!
