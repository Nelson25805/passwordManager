<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![project_license][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/Nelson25805/igdbGameInfo">
    <img src="GithubImages/logo.png" alt="Logo" width="200" height="200">
  </a>

<h3 align="center">Password Manager</h3>


  <p align="center">
    An application to manage your passwords for anything you need.
    <br />
    <a href="https://github.com/Nelson25805/igdbGameInfo"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/Nelson25805/igdbGameInfo">View Demo</a>
    &middot;
    <a href="https://github.com/Nelson25805/igdbGameInfo/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/Nelson25805/igdbGameInfo/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <!-- <li><a href="#roadmap">Roadmap</a></li> -->
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>


<!-- ABOUT THE PROJECT -->
## About The Project

![Project Name Screen Shot][project-screenshot]

The **Ruby Password Manager** is a local password management application designed to securely store, retrieve, and manage login credentials.

### Key features
- 🔐 Local encrypted credential storage (no cloud sync).
- 🗝️ Master password backed authentication.
- 🔍 Per-user encrypted data key (EDK) used to encrypt credentials.
- 💾 One-time recovery token (shown on account creation / regeneration) to recover data if the master password is lost.
- ➕ Add / Edit / Delete credentials.

This project is intended for educational purposes and personal use, focusing on clean Ruby design and fundamental security concepts.
<p align="right">(<a href="#readme-top">back to top</a>)</p>


## Built With

| Badge | Description |
|:-----:|-------------|
| [![Python](GithubImages/pythonShield.svg)][Python-url] | Core programming language. |
| [![PyQt5](GithubImages/pyqt5Shield.svg)][PyQt5-url] | User interface built with PyQt5. |
| [![qdarkstyle](GithubImages/qDarkStyleShield.svg)][qdarkstyle-url] | Polished dark theme support via qdarkstyle. |
| [![IGDB API](GithubImages/igdbApiShield.svg)][igdb-api-url] | Retrieves game data from the IGDB API. |
| [![Pandas](GithubImages/pandasShield.svg)][pandas-url] | Data analysis and manipulation with Pandas. |


<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

To start, you have two options of using this software.
1) Run the .exe file
2) Run the python code script manually

## Installation

1. Clone the repo
   ```sh
   git clone https://github.com/Nelson25805/igdbGameInfo.git
   ```
   
2. If using option 1, skip to step 5.
   If using option 2, continue reading.
   
3. You must have python downloaded on your machine, or in your IDE of choice.
   [Python Download](https://www.python.org/downloads/)

4. Install the required packages:
   ```sh
   pip install -r requirements.txt
   ```
   
5. Create account for IGDB Api requests following their steps:
   [IGDB Api Getting Started](https://api-docs.igdb.com/#getting-started)

7. Create a .env file with your unique CLIENT_ID, and CLIENT_SECRET as shown in this fake test example here:
   ![Project Name Screen Shot][project-screenshot5]

8. Depending on where you run the application, place .env file into same folder as .exe, and or the main project folder. 

9. Either run the application from the .exe in the dlist folder, or by executing:
    ```sh
   python main.py
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

## Filtered Game Search:
![Project Name Screen Shot][project-screenshot2]

This page allows you to search for games with the selected filters, and afterwards save results to a coresponding excel file.


## Random Game Search:
![Project Name Screen Shot][project-screenshot3]

This page allows you to search for a random game in the IGDB database, giving you related information about said game if it's available.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
<!--
## Roadmap

- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3
    - [ ] Nested Feature

See the [open issues](https://github.com/Nelson25805/igdbGameInfo/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>
-->

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Top contributors:

<a href="https://github.com/Nelson25805/igdbGameInfo/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Nelson25805/igdbGameInfo" alt="contrib.rocks image" />
</a>


<!-- LICENSE -->
## License

Distributed under the project_license. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

Nelson McFadyen <!-- - [@twitter_handle](https://twitter.com/twitter_handle) --> - Nelson25805@hotmail.com

Project Link: [https://github.com/Nelson25805/igdbGameInfo](https://github.com/Nelson25805/igdbGameInfo)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/Nelson25805/igdbGameInfo.svg?style=for-the-badge
[contributors-url]: https://github.com/Nelson25805/igdbGameInfo/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Nelson25805/igdbGameInfo.svg?style=for-the-badge
[forks-url]: https://github.com/Nelson25805/igdbGameInfo/network/members
[stars-shield]: https://img.shields.io/github/stars/Nelson25805/igdbGameInfo.svg?style=for-the-badge
[stars-url]: https://github.com/Nelson25805/igdbGameInfo/stargazers
[issues-shield]: https://img.shields.io/github/issues/Nelson25805/igdbGameInfo.svg?style=for-the-badge
[issues-url]: https://github.com/Nelson25805/igdbGameInfo/issues
[license-shield]: https://img.shields.io/github/license/Nelson25805/igdbGameInfo.svg?style=for-the-badge
[license-url]: https://github.com/Nelson25805/igdbGameInfo/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/nelson-mcfadyen-806134133/

[project-Image]: GithubImages/projectImage.png

[project-screenshot]: GithubImages/mainScreen.png
[project-screenshot2]: GithubImages/filteredGameSearch.gif
[project-screenshot3]: GithubImages/randomGameSearch.gif

[project-screenshot4]: GithubImages/excelExample.png
[project-screenshot5]: GithubImages/envExample.png


[Python-url]: https://www.python.org/downloads/
[PyQt5-url]: https://pypi.org/project/PyQt5/
[qdarkstyle-url]: https://pypi.org/project/QDarkStyle/
[igdb-api-url]: https://api-docs.igdb.com/
[pandas-url]: https://pandas.pydata.org/

[Python]: https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54
[Python-url]: https://www.python.org/downloads/
[Tkinter]: https://img.shields.io/badge/Tkinter-8.6-green
[Tkinter-url]: https://docs.python.org/3/library/tkinter.html


[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com 




