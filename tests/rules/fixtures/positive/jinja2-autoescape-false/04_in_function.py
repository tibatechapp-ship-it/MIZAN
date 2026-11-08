from jinja2 import Environment

def build_env(loader):
    return Environment(loader=loader, autoescape=False)
