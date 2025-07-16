README v.3.0 — BitShadow 3.0

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

Ass. Marcos Kayan Niquelatte
