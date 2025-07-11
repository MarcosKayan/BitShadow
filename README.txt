# BitShadow

BitShadow é uma ferramenta gráfica de esteganografia que permite **embutir mensagens criptografadas em imagens PNG** e posteriormente extraí-las com segurança.

## 🔐 Criptografia

O programa utiliza criptografia **AES em modo GCM (Galois/Counter Mode)** para garantir confidencialidade e integridade das mensagens. Além disso, é utilizado:

- **PBKDF2** com 1 milhão de iterações e hash SHA-256 para derivação de chaves com base em senha fornecida pelo usuário.
- **HMAC com SHA-256** para autenticar os dados criptografados.
- Um marcador exclusivo (`BITSHDW1`) é usado para identificar a presença de uma mensagem embutida.

## 📥 Embutir uma Mensagem

1. **Escolha um arquivo PNG** de entrada.
2. **Selecione um arquivo de texto (.txt)** com o conteúdo que deseja ocultar.
3. **Defina uma senha segura.**
4. **Escolha onde salvar a nova imagem PNG** com a mensagem embutida.
5. Clique em **“Encriptar”**.

A imagem gerada conterá os dados criptografados e autenticados, embutidos nos bits menos significativos dos pixels.

⚠️ Certifique-se de que a imagem possui capacidade suficiente para armazenar a mensagem. O programa validará isso automaticamente.

## 📤 Extrair uma Mensagem

1. **Selecione a imagem PNG** que pode conter uma mensagem oculta.
2. **Digite a senha utilizada na hora da inserção.**
3. Clique em **“Desencriptar”**.

O conteúdo será verificado, descriptografado e salvo na pasta que o usuário escolher, com o nome que escolher para o arquivo.txt.

## 🔎 Verificação Rápida

O botão “Selecionar” na aba de desencriptação executa uma verificação automática para determinar se há uma mensagem oculta presente na imagem selecionada.

---

💡 BitShadow é uma forma prática e segura de esconder informações confidenciais dentro de imagens utilizando técnicas modernas de criptografia e esteganografia.


Criado por: Marcos Kayan Niquelatte
