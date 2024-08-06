import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Cria uma sessão de requests
s = requests.Session()
# Define o cabeçalho da sessão, simulando o navegador
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Função para obter todos os formulários de uma URL
def get_forms(url):
    try:
        res = s.get(url)
        res.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar {url}: {e}")
        return []

# Função para extrair os detalhes de um formulário
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

# Função para verificar se uma resposta contém erros comuns de SQL injection
def vulnerable(response):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax"
    }
    
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Função para realizar a varredura de SQL injection
def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + i
                elif input_tag["type"] != "submit": 
                    data[input_tag['name']] = f"test{i}"

            form_action = details['action']
            form_url = urljoin(url, form_action)

            print(f"Testing form action URL: {form_url}")

            try:
                if details["method"] == "post": 
                    res = s.post(form_url, data=data)
                elif details["method"] == "get":
                    res = s.get(form_url, params=data)
                if vulnerable(res):
                    print(f"SQL injection vulnerability detected in form at {form_url}")
                else:
                    print(f"No SQL injection vulnerability detected in form at {form_url}")
            except requests.exceptions.RequestException as e:
                print(f"Erro ao enviar dados para {form_url}: {e}")

# Ponto de entrada do script
if __name__ == "__main__":
    urlToBeChecked = "https://tryhackme.com"
    sql_injection_scan(urlToBeChecked)
