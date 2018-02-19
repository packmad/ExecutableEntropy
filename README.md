- `pip2 install -r requirements.txt`
- `python2 main.py`
- Analisi con `curl`: `curl -X POST -F file=@<file-name-here> http://localhost:5000/`
- Analisi con `python`:
  ```python
  payload = {'file': open('<file-name-here>','rb')}
  r = requests.post('http://localhost:5000/', files=payload)
  print(r.json())
  ```
