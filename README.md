# Mental-health-support-platform

# Mental Health Support Platform

## Overview
The **Mental Health Support Platform** is a database management system designed to assist mental health professionals in managing virtual therapy sessions. It helps organize patient information, track progress, and support continuous care. The system is built for local deployment but can be scaled to cloud platforms like AWS or Google Cloud.

## Features
- **Patient Management**: Organize patient records and therapy sessions.
- **Progress Tracking**: Monitor patient mental health progress over time.
- **AI-Based Therapy Recommendations**: Uses NLP-based sentiment analysis to suggest therapy techniques.
- **Chatbot-Assisted Consultation**: Initial assessment of patient concerns before therapist sessions.
- **Wearable Device Integration**: Tracks stress levels and heart rate using connected devices.

## Technologies Used
- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Flask / streamlit
- **Database**: MySQL
- **AI & ML**: TensorFlow, NLP for sentiment analysis
- **Cloud Deployment**: AWS / Google Cloud (optional)

## Setup Instructions
### Prerequisites
Ensure you have the following installed:
- Python 3.x
- MySQL 
- Flask / Django (depending on your backend choice)


![image](https://github.com/user-attachments/assets/334249cb-08d2-4e42-b276-ada3348f6265)

### Clone the Repository
```sh
 git clone https://github.com/shridharbhat04/Mental-health-support-platform.git
 cd Mental-health-support-platform
```

### Install Dependencies
```sh
 pip install -r requirements.txt
```

### Database Setup
- Configure the **database settings** in the `config.py` file.
- Run database migrations:
```sh
 python manage.py migrate  # Django
 flask db upgrade  # Flask (if using Flask-Migrate)
```

### Run the Application
```sh
 python app.py  # Flask
 python manage.py runserver  # Django
```

### Access the Application
Open a browser and go to `http://127.0.0.1:5000/` (Flask) 

## Future Enhancements
- AI-driven mental health risk prediction.
- Integration with telemedicine services.
- Multi-language support for diverse user accessibility.

## Contributing
Contributions are welcome! Fork the repository, create a feature branch, and submit a pull request.

## License
This project is licensed under the MIT License.

## Contact
For any queries, feel free to reach out via GitHub Issues.
