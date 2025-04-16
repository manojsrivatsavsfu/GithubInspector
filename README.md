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
2. Create a python virtual environment and Install the Dependencies ( Linux/ Mac )

    ```bash
    python3 -m venv env
    source env/bin/activate
    pip install -r requirements.txt
    ```
3. Run the Main analysis script - This will scan a directory or file for vulnerabilities
    ```bash
    python3 main.py exampleActions/
    python3 main.py actions/
    
    ```
    The actions/ directory contains workflows that would trigger all vulnerabilities that we check for. Some examples are curated and some examples are taken from real repos
    The exampleActions/ directory contains curated examples that demonstrate typical vulnerable workflow patterns
4. Run Unit tests
   ```bash
   pytest unit_tests
   ```
  
