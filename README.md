# FlagQuest

FlagQuest is an interactive, educational platform designed to help beginners learn cybersecurity through real-time challenges and comprehensive learning modules. Whether you’re completely new or looking to sharpen your skills, FlagQuest provides hands-on exercises, guided resources, and a competitive leaderboard to track your progress.

## Features

- **Interactive Challenges:**  
  Solve cybersecurity puzzles including SQL Injection, XSS, cryptography, and more.
  
- **Guided Learning Paths:**  
  Access detailed modules with articles, tutorials, and resource links to learn cybersecurity fundamentals from scratch.
  
- **Real-Time Leaderboard:**  
  Compete with peers and monitor your progress with a dynamic leaderboard.
  
- **Hint System:**  
  Request hints to help solve challenges (with point deductions), encouraging smart problem-solving.
  
- **User Authentication & Progress Tracking:**  
  Register and log in to securely track your challenge completions, points, and achievements.
  
- **Admin Panel (Optional):**  
  Manage challenges and monitor user progress (for future expansion).

## Technologies Used

- **Backend:** Python, Flask, Flask-Login, Flask-PyMongo
- **Database:** MongoDB
- **Frontend:** HTML, CSS, Bootstrap, Jinja2 Templating
- **Version Control:** Git, GitHub

## Setup and Installation

### Prerequisites

- Python 3.x
- MongoDB (either installed locally or via MongoDB Atlas)
- Git

### Installation Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/<your_username>/FlagQuest.git
   cd FlagQuest


Set Up a Virtual Environment (Optional but Recommended):

python -m venv env
Activate the virtual environment:

Windows:
bash
Copy
Edit
env\Scripts\activate
macOS/Linux:
bash
Copy
Edit
source env/bin/activate
Install Required Packages:

If you have a requirements.txt, run:

pip install -r requirements.txt
Otherwise, install the necessary packages manually:


pip install Flask Flask-PyMongo Flask-Login Werkzeug
Configure MongoDB:

Ensure that MongoDB is running on your machine on the default port (27017). If you're using a cloud instance (like MongoDB Atlas), update the MONGO_URI in app.py accordingly.

Run the Application:

python app.py
Open your browser and navigate to http://localhost:5000/ to access FlagQuest.

How to Use FlagQuest:

Home Page:
Explore interactive challenges, guided learning paths, and testimonials.

User Registration and Login:
Create an account to securely track your progress and points.

Challenges:
Click on a challenge to attempt solving it. Use the “Show Hint” button (with a point cost) if you need assistance. Challenges unlock sequentially as you complete previous tasks.

Learning Modules:
Visit the “Learn Cyber Security” section to access comprehensive modules with curated articles and resources.

Leaderboard:
Check the real-time leaderboard to see how you rank among peers based on your accumulated points.

Dashboard:
Monitor your personal progress, completed challenges, and points on your dashboard.

Contributing
Contributions are welcome! If you have ideas for improvements or new features, feel free to open an issue or submit a pull request.

License
This project is licensed under the MIT License.

Acknowledgements:

FlagQuest was built as a hackathon project to empower individuals with practical cybersecurity skills.
Thanks to the open-source community and educational resources that inspired this project.