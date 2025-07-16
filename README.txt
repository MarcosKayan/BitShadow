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


# BitShadow 2.0

Esta é a segunda versão do BitShadow, atualizada e ampliada com foco em segurança, flexibilidade e experiência do usuário. Abaixo estão as principais melhorias implementadas em relação à versão original:

1. 🔐 Suporte a Argon2id
   - Adicionado novo sistema de derivação de chaves baseado no algoritmo Argon2id.
   - Parâmetros utilizados: memória 512 MiB, tempo 6 ciclos, paralelismo 4, saída de 64 bytes.
   - Muito mais resistente contra ataques modernos com GPU/ASIC.

2. 🔄 Escolha entre PBKDF2 e Argon2id na interface
   - O usuário pode selecionar o método de derivação diretamente na aba de encriptação.
   - Interface radio-button intuitiva entre os dois algoritmos.

3. 🎯 Detecção automática do algoritmo na desencriptação
   - O programa detecta sozinho se o arquivo foi encriptado com PBKDF2 ou Argon2id.
   - Isso permite compatibilidade reversa com arquivos antigos e interoperabilidade futura.

4. 🖼️ Interface gráfica aprimorada
   - A tela inclui agora seletor de KDF abaixo do campo de senha.
   - Melhor organização visual para campos, botões e progressos.

5. 🧪 Robustez criptográfica reforçada
   - Salt do Argon2 ampliado para 32 bytes.
   - Mantida compatibilidade com PBKDF2 (16 bytes + 1 milhão de iterações).

6. 🛠️ Compatibilidade com versões anteriores
   - Arquivos PNG gerados com BitShadow 1.0 podem ser desencriptados normalmente.
   - Fluxo de desencriptação totalmente automatizado.

Esta versão representa um avanço técnico e estrutural, mantendo a simplicidade de uso e a robustez da proposta original.


BitShadow 3.0

Esta é a terceira versão do BitShadow, atualizada e ampliada com foco em ainda mais segurança, flexibilidade e experiência do usuário. Abaixo estão as principais melhorias implementadas em relação à versão original:

🔒 Segurança e Esteganografia
Esteganografia com dispersão aleatória: Os bits do payload são agora inseridos de forma dispersa com base em um seed aleatório (armazenado no início da imagem). Isso torna a ocultação mais resistente à análise estatística.

Autenticidade via HMAC pré-extração: A verificação da senha agora pode ser feita antes da extração da mensagem, permitindo detectar mensagens válidas de forma segura sem tentar descriptografar.

Salt de tamanho variável (configurável pelo usuário) para derivação da chave com Argon2id.

Assinatura HMAC sobre cabeçalho criptográfico dinâmico, protegendo integridade de metadados (salt, tamanho, etc.).

Nova estrutura de cabeçalho criptográfico com campos compactos, facilitando a autenticação e extração segura.

------------------------------------------------------------------------------

⚙️ Parâmetros Argon2id ajustáveis

Interface gráfica aprimorada permite ajustar:

Tamanho do salt (16, 32 ou 64 bytes)

Número de iterações (time cost)

Quantidade de memória em MB

Paralelismo (número de threads)

------------------------------------------------------------------------------

🖱️ Suporte a arrastar-e-soltar (Drag & Drop)

------------------------------------------------------------------------------

Em linhas gerais, o programa se tornou mais seguro quanto à possibilidade de detecção da presença de esteganografia nas imagens PNG, bem como passou a permitir que o usuário utilize parâmetros ainda mais robustos para a derivação da chave via Argon2id, que agora é o único KDF presente.

De todo modo, a segurança é garantida, em último caso, pela força da senha escolhida pelo usuário.

Nem mesmo a melhor criptografia do mundo é capaz de proteger uma senha fraca.


Criado por: Marcos Kayan Niquelatte
