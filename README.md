# GitHub Inspector
Github Actions Inspector


### Prerequisites

- Python 3.7 or higher

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/manojsrivatsavsfu/GithubInspector.git
   cd GithubInspector
   ```
2. Create a python virtual environment and Install the Dependencies

    ```bash
    python3 -m venv env
    source env/bin/activate
    pip install -r requirements.txt
    ```
3. Run the Main analysis script - This will scan a directory or file for vulnerabilities
    ```bash
    python3 main.py [name of file/directory which contains github workflows]
    ```
4. Run Unit tests
   ```bash
   pytest unit_tests
   ```
  
