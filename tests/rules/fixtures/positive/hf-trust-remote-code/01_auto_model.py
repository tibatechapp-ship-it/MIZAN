from transformers import AutoModel

model = AutoModel.from_pretrained(name, trust_remote_code=True)
