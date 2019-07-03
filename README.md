# Snorpy
Snorpy is a simple Snort rule creator / builder / maker made originally with python but I made the most recent version with Node and jquery. 

This sample can be seen at <a href="http://snorpy.com">Snorpy.com</a>


# Docker Installation Instructions:

1. Download and install Docker-ce
2. git clone https://github.com/chrisjd20/Snorpy.git
3. cd Snorpy
4. docker build -t snorpy_app .
5. docker run -p 8080:8080 -it --rm --name snorpy_container snorpy_app
